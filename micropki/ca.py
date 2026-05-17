import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from .crypto_utils import read_passphrase_from_file
from .templates import parse_san_entry, get_template_extensions, TemplateError
from .database import (
    add_certificate, init_db, get_certificate_by_serial,
    update_certificate_status, get_revoked_certificates,
    get_crl_metadata, update_crl_metadata
)
from .serial import generate_unique_serial, serial_to_hex
from .crl import generate_crl, save_crl

VALID_REASONS = [
    "unspecified", "keyCompromise", "cACompromise", "affiliationChanged",
    "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL",
    "privilegeWithdrawn", "aACompromise"
]


# ==========================================
# БЛОК 1: Утилиты (Sprint 1-3)
# ==========================================

def generate_key_pair(key_type: str, key_size: int):
    if key_type == "rsa":
        if key_size is None: key_size = 4096
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    elif key_type == "ecc":
        if key_size == 384 or key_size is None:
            private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
        elif key_size == 256:
            private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        else:
            raise ValueError(f"Unsupported ECC size: {key_size}")
    else:
        raise ValueError(f"Unsupported key type: {key_type}")
    return private_key


def parse_subject_name(subject_str: str) -> x509.Name:
    attributes = []
    clean_subject = subject_str.lstrip('/')
    parts = clean_subject.split(',')
    for part in parts:
        part = part.strip()
        if '=' not in part: continue
        oid_name, value = part.split('=', 1)
        oid_map = {
            'CN': NameOID.COMMON_NAME, 'O': NameOID.ORGANIZATION_NAME,
            'OU': NameOID.ORGANIZATIONAL_UNIT_NAME, 'C': NameOID.COUNTRY_NAME,
            'ST': NameOID.STATE_OR_PROVINCE_NAME, 'L': NameOID.LOCALITY_NAME,
            'EMAIL': NameOID.EMAIL_ADDRESS,
        }
        if oid_name.strip() in oid_map:
            attributes.append(x509.NameAttribute(oid_map[oid_name.strip()], value.strip()))
    return x509.Name(attributes)


def save_encrypted_key(private_key, passphrase: bytes, output_path: Path):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )
    output_path.write_bytes(pem)
    try:
        os.chmod(output_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def save_certificate(cert: x509.Certificate, output_path: Path):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    output_path.write_bytes(pem)


def create_policy_file(out_dir: Path, subject: str, serial: int, validity_days: int, key_type: str, key_size: int,
                       issuer: str = None):
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=validity_days)
    content = f"\n--- Certificate Entry ---\nSubject: {subject}\nSerial: {hex(serial)}\nValidity: {now.strftime('%Y-%m-%d')} to {not_after.strftime('%Y-%m-%d')}\nAlgorithm: {key_type.upper()} {key_size} bits\n"
    if issuer:
        content += f"Issuer: {issuer}\n"
    else:
        content += "Type: Self-Signed Root CA\n"

    policy_path = out_dir / "policy.txt"
    with open(policy_path, "a", encoding='utf-8') as f:
        f.write(content)


# ==========================================
# БЛОК 2: Логика Root CA (Sprint 1)
# ==========================================

def create_self_signed_cert(private_key, subject_name: x509.Name, validity_days: int) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    serial_number = x509.random_serial_number()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name).issuer_name(subject_name).public_key(private_key.public_key())
    builder = builder.serial_number(serial_number).not_valid_before(now).not_valid_after(
        now + timedelta(days=validity_days))
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                      encipher_only=False, decipher_only=False), critical=True
    )
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        ), critical=False
    )
    sig_algo = hashes.SHA256() if isinstance(private_key, rsa.RSAPrivateKey) else hashes.SHA384()
    return builder.sign(private_key, sig_algo, default_backend())


def initialize_ca(args, logger):
    logger.info("Starting Root CA initialization...")
    passphrase = read_passphrase_from_file(args.passphrase_file)
    logger.info(f"Generating {args.key_type.upper()} key...")
    private_key = generate_key_pair(args.key_type, args.key_size)
    subject_name = parse_subject_name(args.subject)
    logger.info("Creating self-signed certificate...")
    cert = create_self_signed_cert(private_key, subject_name, args.validity_days)

    out_dir = Path(args.out_dir)
    private_dir = out_dir / "private"
    certs_dir = out_dir / "certs"
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    certs_dir.mkdir(parents=True, exist_ok=True)

    save_encrypted_key(private_key, passphrase, private_dir / "ca.key.pem")
    save_certificate(cert, certs_dir / "ca.cert.pem")
    create_policy_file(out_dir, args.subject, cert.serial_number, args.validity_days, args.key_type, args.key_size)

    # Sprint 3: Запись в БД
    db_path = getattr(args, 'db_path', None)
    if db_path:
        try:
            if not Path(db_path).exists(): init_db(db_path)
            pem_data = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            add_certificate(db_path, serial_to_hex(cert.serial_number), subject_name.rfc4514_string(),
                            subject_name.rfc4514_string(), cert.not_valid_before_utc, cert.not_valid_after_utc,
                            pem_data)
            logger.info("Root CA added to database.")
        except Exception as e:
            logger.warning(f"Could not add Root CA to DB: {e}")

    logger.info("Root CA initialization completed.")


# ==========================================
# БЛОК 3: Логика Intermediate CA (Sprint 2 + 3)
# ==========================================

def create_intermediate_ca(args, logger):
    logger.info("Starting Intermediate CA creation...")
    with open(args.root_cert, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
    root_pass = read_passphrase_from_file(args.root_pass_file)
    with open(args.root_key, "rb") as f:
        root_key = serialization.load_pem_private_key(f.read(), password=root_pass, backend=default_backend())

    logger.info(f"Generating Intermediate CA key ({args.key_type.upper()})...")
    int_key = generate_key_pair(args.key_type, args.key_size)
    subject_name = parse_subject_name(args.subject)

    logger.info("Creating CSR...")
    builder = x509.CertificateSigningRequestBuilder(subject_name=subject_name)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=args.pathlen), critical=True)
    csr = builder.sign(int_key, hashes.SHA256(), default_backend())

    logger.info("Signing Intermediate CA certificate...")
    now = datetime.now(timezone.utc)
    serial_int = generate_unique_serial()

    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject_name).issuer_name(root_cert.subject).public_key(
        int_key.public_key())
    cert_builder = cert_builder.serial_number(serial_int).not_valid_before(now).not_valid_after(
        now + timedelta(days=args.validity_days))
    cert_builder = cert_builder.add_extension(x509.BasicConstraints(ca=True, path_length=args.pathlen), critical=True)
    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                      encipher_only=False, decipher_only=False), critical=True
    )
    cert_builder = cert_builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()),
                                              critical=False)
    try:
        root_ski = root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski), critical=False)
    except x509.ExtensionNotFound:
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()), critical=False)

    sig_algo = hashes.SHA256() if isinstance(root_key, rsa.RSAPrivateKey) else hashes.SHA384()
    int_cert = cert_builder.sign(root_key, sig_algo, default_backend())

    out_dir = Path(args.out_dir)
    private_dir = out_dir / "private"
    certs_dir = out_dir / "certs"
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    certs_dir.mkdir(parents=True, exist_ok=True)

    cert_pem_data = int_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    # Sprint 3: Запись в БД
    db_path = getattr(args, 'db_path', None)
    if db_path:
        try:
            if not Path(db_path).exists(): init_db(db_path)
            add_certificate(db_path, serial_to_hex(serial_int), subject_name.rfc4514_string(),
                            root_cert.subject.rfc4514_string(), int_cert.not_valid_before_utc,
                            int_cert.not_valid_after_utc, cert_pem_data)
            logger.info("Intermediate CA added to database.")
        except Exception as e:
            logger.error(f"DB error: {e}. Aborting file save.")
            raise RuntimeError("Failed to save to DB") from e

    save_encrypted_key(int_key, read_passphrase_from_file(args.passphrase_file), private_dir / "intermediate.key.pem")
    save_certificate(int_cert, certs_dir / "intermediate.cert.pem")
    create_policy_file(out_dir, args.subject, serial_int, args.validity_days, args.key_type, args.key_size,
                       issuer=root_cert.subject.rfc4514_string())
    logger.info("Intermediate CA creation completed.")


# ==========================================
# БЛОК 4: Логика Leaf Certificates (Sprint 2 + 3)
# ==========================================

def issue_end_entity_cert(args, logger):
    logger.info(f"Starting certificate issuance (Template: {args.template})...")
    with open(args.ca_cert, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    ca_pass = read_passphrase_from_file(args.ca_pass_file)
    with open(args.ca_key, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=ca_pass, backend=default_backend())

    subject_name = parse_subject_name(args.subject)
    k_type = "rsa"

    if args.csr:
        with open(args.csr, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
        if not csr.is_signature_valid: raise ValueError("Invalid CSR signature.")
        public_key = csr.public_key()
        subject_name = csr.subject
        if isinstance(public_key, ec.EllipticCurvePublicKey): k_type = "ecc"
    else:
        logger.info("Generating new end-entity key pair...")
        if isinstance(ca_key, ec.EllipticCurvePrivateKey):
            leaf_key = ec.generate_private_key(ec.SECP256R1(), default_backend());
            k_type = "ecc"
        else:
            leaf_key = rsa.generate_private_key(65537, 2048, default_backend());
            k_type = "rsa"
        public_key = leaf_key.public_key()

    san_list = [parse_san_entry(s) for s in args.san]
    try:
        extensions = get_template_extensions(args.template, san_list, k_type)
    except TemplateError as e:
        logger.error(f"Template validation failed: {e}");
        raise

    logger.info("Signing certificate...")
    now = datetime.now(timezone.utc)
    serial_int = generate_unique_serial()

    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject_name).issuer_name(ca_cert.subject).public_key(public_key)
    cert_builder = cert_builder.serial_number(serial_int).not_valid_before(now).not_valid_after(
        now + timedelta(days=args.validity_days))
    for ext in extensions: cert_builder = cert_builder.add_extension(ext.value, critical=ext.critical)
    cert_builder = cert_builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    try:
        ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
    except x509.ExtensionNotFound:
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)

    sig_algo = hashes.SHA256() if isinstance(ca_key, rsa.RSAPrivateKey) else hashes.SHA384()
    leaf_cert = cert_builder.sign(ca_key, sig_algo, default_backend())

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_pem_data = leaf_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    # Sprint 3: Запись в БД
    db_path = getattr(args, 'db_path', None)
    if db_path:
        try:
            if not Path(db_path).exists(): init_db(db_path)
            add_certificate(db_path, serial_to_hex(serial_int), subject_name.rfc4514_string(),
                            ca_cert.subject.rfc4514_string(), leaf_cert.not_valid_before_utc,
                            leaf_cert.not_valid_after_utc, cert_pem_data)
            logger.info("Certificate added to database.")
        except Exception as e:
            logger.error(f"DB error: {e}. Aborting file save.")
            raise RuntimeError("Failed to save to DB") from e

    cn_attrs = subject_name.get_attributes_for_oid(NameOID.COMMON_NAME)
    base_name = cn_attrs[0].value if cn_attrs else serial_to_hex(serial_int)[-8:]
    base_name = base_name.replace(" ", "_").replace("*", "_wildcard_")

    save_certificate(leaf_cert, out_dir / f"{base_name}.cert.pem")
    if not args.csr:
        key_path = out_dir / f"{base_name}.key.pem"
        pem = leaf_key.private_bytes(encoding=serialization.Encoding.PEM,
                                     format=serialization.PrivateFormat.TraditionalOpenSSL,
                                     encryption_algorithm=serialization.NoEncryption())
        key_path.write_bytes(pem)
        try:
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        logger.warning(f"Unencrypted private key saved: {key_path}")

    logger.info(
        f"AUDIT: Issued {args.template} cert for {subject_name.rfc4514_string()} (Serial: {serial_to_hex(serial_int)})")
    logger.info("Certificate issuance completed.")


# ==========================================
# БЛОК 5: НОВЫЕ ФУНКЦИИ СПРИНТА 4 (CRL)
# ==========================================

def revoke_certificate(args, logger):
    """Отзыв сертификата по серийному номеру"""
    serial_hex = args.serial.upper()
    reason = args.reason if args.reason else "unspecified"
    db_path = getattr(args, 'db_path', "./pki/micropki.db")

    if reason not in VALID_REASONS:
        raise ValueError(f"Invalid reason: {reason}. Allowed: {', '.join(VALID_REASONS)}")

    cert = get_certificate_by_serial(db_path, serial_hex)
    if not cert:
        logger.error(f"Certificate {serial_hex} not found in database.")
        raise ValueError("Certificate not found")

    if cert['status'] == 'revoked':
        logger.warning(f"Certificate {serial_hex} is already revoked.")
        return

    update_certificate_status(db_path, serial_hex, 'revoked', reason)
    logger.info(f"Certificate {serial_hex} successfully revoked. Reason: {reason}")
    logger.info("Run 'ca gen-crl' to update the CRL file.")


def generate_crl_cli(args, logger):
    """Генерация файла CRL"""
    ca_level = args.ca.lower()
    next_update_days = args.next_update
    out_file = args.out_file
    db_path = getattr(args, 'db_path', "./pki/micropki.db")
    out_dir = Path(getattr(args, 'out_dir', "./pki"))

    # Определение путей
    if ca_level == 'root':
        cert_path = out_dir / "certs" / "ca.cert.pem"
        key_path = out_dir / "private" / "ca.key.pem"
        pass_arg = args.root_pass_file
        default_out = out_dir / "crl" / "root.crl.pem"
    elif ca_level == 'intermediate':
        cert_path = out_dir / "certs" / "intermediate.cert.pem"
        key_path = out_dir / "private" / "intermediate.key.pem"
        pass_arg = args.ca_pass_file
        default_out = out_dir / "crl" / "intermediate.crl.pem"
    else:
        raise ValueError("CA must be 'root' or 'intermediate'")

    target_path = Path(out_file) if out_file else default_out

    # Загрузка CA
    if not cert_path.exists(): raise FileNotFoundError(f"CA certificate not found: {cert_path}")
    with open(cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    if not key_path.exists(): raise FileNotFoundError(f"CA key not found: {key_path}")

    # Поиск пароля
    if not pass_arg:
        default_pass = out_dir.parent / "secrets" / ("root.pass" if ca_level == 'root' else "intermediate.pass")
        if default_pass.exists():
            pass_arg = str(default_pass)
        else:
            raise FileNotFoundError("Passphrase file not provided or found.")

    ca_pass = read_passphrase_from_file(pass_arg)
    with open(key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=ca_pass, backend=default_backend())

    # Получение отозванных
    revoked_list = get_revoked_certificates(db_path, issuer_dn=ca_cert.subject.rfc4514_string())
    logger.info(f"Found {len(revoked_list)} revoked certificates for {ca_level} CA.")

    # Номер CRL
    meta = get_crl_metadata(db_path, ca_cert.subject.rfc4514_string())
    crl_num = (meta['crl_number'] + 1) if meta else 1

    # Генерация
    logger.info(f"Generating CRL #{crl_num}...")
    crl_pem = generate_crl(
        ca_cert=ca_cert, ca_key=ca_key, revoked_certs=revoked_list,
        next_update_days=next_update_days, crl_number=crl_num
    )

    save_crl(crl_pem, target_path)
    logger.info(f"CRL saved to: {target_path}")

    update_crl_metadata(
        db_path=db_path, ca_subject=ca_cert.subject.rfc4514_string(),
        crl_number=crl_num, next_update=datetime.now(timezone.utc) + timedelta(days=next_update_days),
        crl_path=str(target_path)
    )
    logger.info("CRL metadata updated in database.")