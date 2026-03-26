import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
import ipaddress

from .crypto_utils import read_passphrase_from_file
from .templates import parse_san_entry, get_template_extensions, TemplateError
from .database import add_certificate, init_db
from .serial import generate_unique_serial, serial_to_hex

def generate_key_pair(key_type: str, key_size: int):
    if key_type == "rsa":
        if key_size is None:
            key_size = 4096
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
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
        if '=' not in part:
            continue
        oid_name, value = part.split('=', 1)
        oid_name = oid_name.strip()
        value = value.strip()

        oid_map = {
            'CN': NameOID.COMMON_NAME,
            'O': NameOID.ORGANIZATION_NAME,
            'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
            'C': NameOID.COUNTRY_NAME,
            'ST': NameOID.STATE_OR_PROVINCE_NAME,
            'L': NameOID.LOCALITY_NAME,
            'EMAIL': NameOID.EMAIL_ADDRESS,
        }

        if oid_name in oid_map:
            attributes.append(x509.NameAttribute(oid_map[oid_name], value))

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

    content = f"""
--- Certificate Entry ---
Subject: {subject}
Serial Number: {hex(serial)}
Validity Period: {now.strftime('%Y-%m-%d')} to {not_after.strftime('%Y-%m-%d')}
Key Algorithm: {key_type.upper()}
Key Size: {key_size} bits
"""
    if issuer:
        content += f"Issuer: {issuer}\n"
    else:
        content += "Type: Self-Signed Root CA\n"

    content += f"Creation Date: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"

    policy_path = out_dir / "policy.txt"
    with open(policy_path, "a", encoding='utf-8') as f:
        f.write(content)

def create_self_signed_cert(private_key, subject_name: x509.Name, validity_days: int) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    serial_number = x509.random_serial_number()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(subject_name)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(serial_number)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=validity_days))

    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                      encipher_only=False, decipher_only=False),
        critical=True
    )

    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        ),
        critical=False
    )

    sig_algo = hashes.SHA256() if isinstance(private_key, rsa.RSAPrivateKey) else hashes.SHA384()
    return builder.sign(private_key, sig_algo, default_backend())


def initialize_ca(args, logger):
    logger.info("Starting Root CA initialization...")
    passphrase = read_passphrase_from_file(args.passphrase_file)

    logger.info(f"Generating {args.key_type.upper()} key pair ({args.key_size} bits)...")
    private_key = generate_key_pair(args.key_type, args.key_size)
    logger.info("Key generation completed.")

    subject_name = parse_subject_name(args.subject)
    logger.info("Creating self-signed X.509 certificate...")
    cert = create_self_signed_cert(private_key, subject_name, args.validity_days)
    logger.info(f"Certificate created. Serial: {hex(cert.serial_number)}")

    out_dir = Path(args.out_dir)
    private_dir = out_dir / "private"
    certs_dir = out_dir / "certs"
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    certs_dir.mkdir(parents=True, exist_ok=True)

    key_path = private_dir / "ca.key.pem"
    save_encrypted_key(private_key, passphrase, key_path)
    logger.info(f"Encrypted private key saved to: {key_path}")

    cert_path = certs_dir / "ca.cert.pem"
    save_certificate(cert, cert_path)
    logger.info(f"Certificate saved to: {cert_path}")

    create_policy_file(out_dir, args.subject, cert.serial_number, args.validity_days, args.key_type, args.key_size)
    logger.info(f"Policy document saved/updated.")

    db_path = getattr(args, 'db_path', None)
    if db_path and Path(db_path).exists():
        try:
            pem_data = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            add_certificate(
                db_path=db_path,
                serial_hex=serial_to_hex(cert.serial_number),
                subject=subject_name.rfc4514_string(),
                issuer=subject_name.rfc4514_string(),
                not_before=cert.not_valid_before_utc,
                not_after=cert.not_valid_after_utc,
                cert_pem=pem_data,
                status="valid"
            )
            logger.info(f"Root CA added to database: {db_path}")
        except Exception as e:
            logger.warning(f"Could not add Root CA to database: {e}")

    logger.info("Root CA initialization completed successfully.")

def create_intermediate_ca(args, logger):
    logger.info("Starting Intermediate CA creation...")
    logger.info("Loading Root CA credentials...")
    with open(args.root_cert, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())

    root_pass = read_passphrase_from_file(args.root_pass_file)
    with open(args.root_key, "rb") as f:
        root_key = serialization.load_pem_private_key(f.read(), password=root_pass, backend=default_backend())

    logger.info(f"Generating Intermediate CA key ({args.key_type.upper()})...")
    int_key = generate_key_pair(args.key_type, args.key_size)

    subject_name = parse_subject_name(args.subject)

    logger.info("Creating CSR for Intermediate CA...")
    builder = x509.CertificateSigningRequestBuilder(subject_name=subject_name)
    bc_ext = x509.BasicConstraints(ca=True, path_length=args.pathlen)
    builder = builder.add_extension(bc_ext, critical=True)
    csr = builder.sign(int_key, hashes.SHA256(), default_backend())
    logger.info("CSR generated successfully.")

    logger.info("Signing Intermediate CA certificate with Root CA...")
    now = datetime.now(timezone.utc)

    serial_int = generate_unique_serial()
    serial_hex = serial_to_hex(serial_int)
    logger.info(f"Generated unique serial: {serial_hex}")

    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject_name)
    cert_builder = cert_builder.issuer_name(root_cert.subject)
    cert_builder = cert_builder.public_key(int_key.public_key())
    cert_builder = cert_builder.serial_number(serial_int)
    cert_builder = cert_builder.not_valid_before(now)
    cert_builder = cert_builder.not_valid_after(now + timedelta(days=args.validity_days))

    cert_builder = cert_builder.add_extension(x509.BasicConstraints(ca=True, path_length=args.pathlen), critical=True)
    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                      encipher_only=False, decipher_only=False),
        critical=True
    )
    cert_builder = cert_builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()),
                                              critical=False)

    try:
        root_ski = root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski), critical=False
        )
    except x509.ExtensionNotFound:
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()), critical=False
        )

    sig_algo = hashes.SHA256() if isinstance(root_key, rsa.RSAPrivateKey) else hashes.SHA384()
    int_cert = cert_builder.sign(root_key, sig_algo, default_backend())
    logger.info(f"Intermediate CA certificate signed.")

    out_dir = Path(args.out_dir)
    private_dir = out_dir / "private"
    certs_dir = out_dir / "certs"
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    certs_dir.mkdir(parents=True, exist_ok=True)

    cert_pem_data = int_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    db_path = getattr(args, 'db_path', None)
    if db_path:
        logger.info(f"Saving Intermediate CA to database: {db_path}")
        try:
            if not Path(db_path).exists():
                init_db(db_path)

            add_certificate(
                db_path=db_path,
                serial_hex=serial_hex,
                subject=subject_name.rfc4514_string(),
                issuer=root_cert.subject.rfc4514_string(),
                not_before=int_cert.not_valid_before_utc,
                not_after=int_cert.not_valid_after_utc,
                cert_pem=cert_pem_data,
                status="valid"
            )
            logger.info("Database record created successfully.")
        except Exception as e:
            logger.error(f"Database insertion failed: {e}. Certificate files will NOT be saved.")
            raise RuntimeError("Failed to save certificate to database. Aborting issuance.") from e
    else:
        logger.warning("No database path provided. Certificate issued but not recorded in DB.")

    int_key_path = private_dir / "intermediate.key.pem"
    int_pass = read_passphrase_from_file(args.passphrase_file)
    save_encrypted_key(int_key, int_pass, int_key_path)
    logger.info(f"Intermediate CA key saved: {int_key_path}")

    int_cert_path = certs_dir / "intermediate.cert.pem"
    save_certificate(int_cert, int_cert_path)
    logger.info(f"Intermediate CA cert saved: {int_cert_path}")

    create_policy_file(out_dir, args.subject, serial_int, args.validity_days, args.key_type, args.key_size,
                       issuer=root_cert.subject.rfc4514_string())
    logger.info("Intermediate CA creation completed.")

def issue_end_entity_cert(args, logger):
    logger.info(f"Starting certificate issuance (Template: {args.template})...")

    logger.info("Loading Intermediate CA credentials...")
    with open(args.ca_cert, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    ca_pass = read_passphrase_from_file(args.ca_pass_file)
    with open(args.ca_key, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=ca_pass, backend=default_backend())

    subject_name = parse_subject_name(args.subject)
    k_type = "rsa"

    if args.csr:
        logger.info(f"Loading external CSR: {args.csr}")
        with open(args.csr, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
        if not csr.is_signature_valid:
            raise ValueError("Invalid CSR signature.")
        public_key = csr.public_key()
        subject_name = csr.subject
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            k_type = "ecc"
    else:
        logger.info("Generating new end-entity key pair...")
        if isinstance(ca_key, ec.EllipticCurvePrivateKey):
            leaf_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            k_type = "ecc"
        else:
            leaf_key = rsa.generate_private_key(65537, 2048, default_backend())
            k_type = "rsa"
        public_key = leaf_key.public_key()

    san_list = []
    for san_entry in args.san:
        san_list.append(parse_san_entry(san_entry))

    try:
        extensions = get_template_extensions(args.template, san_list, k_type)
    except TemplateError as e:
        logger.error(f"Template validation failed: {e}")
        raise

    logger.info("Signing certificate with Intermediate CA...")
    now = datetime.now(timezone.utc)

    serial_int = generate_unique_serial()
    serial_hex = serial_to_hex(serial_int)
    logger.info(f"Generated unique serial: {serial_hex}")

    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject_name)
    cert_builder = cert_builder.issuer_name(ca_cert.subject)
    cert_builder = cert_builder.public_key(public_key)
    cert_builder = cert_builder.serial_number(serial_int)
    cert_builder = cert_builder.not_valid_before(now)
    cert_builder = cert_builder.not_valid_after(now + timedelta(days=args.validity_days))

    for ext in extensions:
        cert_builder = cert_builder.add_extension(ext.value, critical=ext.critical)

    cert_builder = cert_builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    try:
        ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False
        )
    except x509.ExtensionNotFound:
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
        )

    sig_algo = hashes.SHA256() if isinstance(ca_key, rsa.RSAPrivateKey) else hashes.SHA384()
    leaf_cert = cert_builder.sign(ca_key, sig_algo, default_backend())
    logger.info(f"Certificate issued.")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cert_pem_data = leaf_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    db_path = getattr(args, 'db_path', None)
    if db_path:
        logger.info(f"Saving certificate to database: {db_path}")
        try:
            if not Path(db_path).exists():
                init_db(db_path)

            add_certificate(
                db_path=db_path,
                serial_hex=serial_hex,
                subject=subject_name.rfc4514_string(),
                issuer=ca_cert.subject.rfc4514_string(),
                not_before=leaf_cert.not_valid_before_utc,
                not_after=leaf_cert.not_valid_after_utc,
                cert_pem=cert_pem_data,
                status="valid"
            )
            logger.info("Database record created successfully.")
        except Exception as e:
            logger.error(f"Database insertion failed: {e}. Aborting file save.")
            raise RuntimeError("Failed to save certificate to database.") from e

    cn_attrs = subject_name.get_attributes_for_oid(NameOID.COMMON_NAME)
    base_name = cn_attrs[0].value if cn_attrs else serial_hex[-8:]
    base_name = base_name.replace(" ", "_").replace("*", "_wildcard_")

    cert_path = out_dir / f"{base_name}.cert.pem"
    save_certificate(leaf_cert, cert_path)
    logger.info(f"Certificate saved: {cert_path}")

    if not args.csr:
        key_path = out_dir / f"{base_name}.key.pem"
        pem = leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        key_path.write_bytes(pem)
        try:
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        logger.warning(f"Unencrypted private key saved: {key_path}")

    logger.info(f"AUDIT: Issued {args.template} cert for {subject_name.rfc4514_string()} (Serial: {serial_hex})")
    logger.info("Certificate issuance completed.")