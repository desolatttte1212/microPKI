from __future__ import annotations
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import AccessDescription, GeneralName

from .crypto_utils import read_passphrase_from_file
from .templates import parse_san_entry, get_template_extensions, TemplateError
from .database import (
    add_certificate, init_db, get_certificate_by_serial,
    update_certificate_status, get_revoked_certificates,
    get_crl_metadata, update_crl_metadata
)
from .serial import generate_unique_serial, serial_to_hex
from .crl import generate_crl, save_crl
from .policy import (
    check_key_size, check_validity_period, check_san_policy,
    check_signature_algorithm, check_path_length, PolicyError
)
from .compromise import is_key_compromised

VALID_REASONS = [
    "unspecified", "keyCompromise", "cACompromise", "affiliationChanged",
    "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL",
    "privilegeWithdrawn", "aACompromise"
]


# ==========================================
# БЛОК 1: Утилиты
# ==========================================

def generate_key_pair(key_type: str, key_size: int):
    if key_type == "rsa":
        if key_size is None: key_size = 4096
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    elif key_type == "ecc":
        curve = ec.SECP384R1() if key_size in (None, 384) else ec.SECP256R1()
        return ec.generate_private_key(curve, backend=default_backend())
    raise ValueError(f"Unsupported key type: {key_type}")


def parse_subject_name(subject_str: str) -> x509.Name:
    attributes = []
    clean_subject = subject_str.lstrip('/')
    oid_map = {
        'CN': NameOID.COMMON_NAME, 'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME, 'C': NameOID.COUNTRY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME, 'L': NameOID.LOCALITY_NAME,
        'EMAIL': NameOID.EMAIL_ADDRESS,
    }
    for part in clean_subject.split(','):
        part = part.strip()
        if '=' not in part: continue
        oid_name, value = part.split('=', 1)
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
    output_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def create_policy_file(out_dir: Path, subject: str, serial: int, validity_days: int, key_type: str, key_size: int,
                       issuer: str = None):
    now = datetime.now(timezone.utc)
    content = f"\n--- Certificate Entry ---\nSubject: {subject}\nSerial: {hex(serial)}\nValidity: {now.strftime('%Y-%m-%d')} to {(now + timedelta(days=validity_days)).strftime('%Y-%m-%d')}\nAlgorithm: {key_type.upper()} {key_size} bits\n"
    if issuer:
        content += f"Issuer: {issuer}\n"
    else:
        content += "Type: Self-Signed Root CA\n"
    with open(out_dir / "policy.txt", "a", encoding='utf-8') as f:
        f.write(content)


# ==========================================
# БЛОК 2: Root CA (Sprint 1)
# ==========================================

def create_self_signed_cert(private_key, subject_name: x509.Name, validity_days: int) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name).issuer_name(subject_name).public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(
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

    # Аудит начала операции
    if hasattr(args, 'audit_logger'):
        args.audit_logger.audit(
            operation="ca_init",
            status="started",
            message="Root CA initialization started",
            metadata={"subject": args.subject, "key_type": args.key_type}
        )

    try:
        passphrase = read_passphrase_from_file(args.passphrase_file)
        private_key = generate_key_pair(args.key_type, args.key_size)
        subject_name = parse_subject_name(args.subject)

        # Проверка политик для Root CA
        check_key_size(private_key, "root_ca", args.key_type)
        check_validity_period(args.validity_days, "root_ca")

        cert = create_self_signed_cert(private_key, subject_name, args.validity_days)

        out_dir = Path(args.out_dir)
        private_dir = out_dir / "private"
        certs_dir = out_dir / "certs"
        private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        certs_dir.mkdir(parents=True, exist_ok=True)

        save_encrypted_key(private_key, passphrase, private_dir / "ca.key.pem")
        save_certificate(cert, certs_dir / "ca.cert.pem")
        create_policy_file(out_dir, args.subject, cert.serial_number, args.validity_days, args.key_type, args.key_size)

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

        # Аудит успешного завершения
        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="ca_init",
                status="success",
                message="Root CA initialized successfully",
                metadata={"serial": serial_to_hex(cert.serial_number), "subject": subject_name.rfc4514_string()}
            )
        logger.info("Root CA initialization completed.")

    except PolicyError as e:
        logger.error(f"Policy violation: {e}")
        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="ca_init",
                status="failure",
                message=f"Policy violation: {e}",
                metadata={"subject": args.subject}
            )
        raise
    except Exception as e:
        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="ca_init",
                status="failure",
                message=f"Error: {str(e)}",
                metadata={"subject": args.subject}
            )
        raise


# ==========================================
# БЛОК 3: Intermediate CA (Sprint 2)
# ==========================================

def create_intermediate_ca(args, logger):
    logger.info("Starting Intermediate CA creation...")

    if hasattr(args, 'audit_logger'):
        args.audit_logger.audit(
            operation="ca_init",
            status="started",
            message="Intermediate CA creation started",
            metadata={"subject": args.subject}
        )

    try:
        with open(args.root_cert, "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())
        root_pass = read_passphrase_from_file(args.root_pass_file)
        with open(args.root_key, "rb") as f:
            root_key = serialization.load_pem_private_key(f.read(), password=root_pass, backend=default_backend())

        int_key = generate_key_pair(args.key_type, args.key_size)
        subject_name = parse_subject_name(args.subject)

        # Проверка политик
        check_key_size(int_key, "intermediate_ca", args.key_type)
        check_validity_period(args.validity_days, "intermediate_ca")
        if hasattr(args, 'pathlen'):
            check_path_length(args.pathlen, "intermediate_ca")

        builder = x509.CertificateSigningRequestBuilder(subject_name=subject_name)
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=args.pathlen), critical=True)
        csr = builder.sign(int_key, hashes.SHA256(), default_backend())

        now = datetime.now(timezone.utc)
        serial_int = generate_unique_serial()
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject_name).issuer_name(root_cert.subject).public_key(
            int_key.public_key())
        cert_builder = cert_builder.serial_number(serial_int).not_valid_before(now).not_valid_after(
            now + timedelta(days=args.validity_days))
        cert_builder = cert_builder.add_extension(x509.BasicConstraints(ca=True, path_length=args.pathlen),
                                                  critical=True)
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

        save_encrypted_key(int_key, read_passphrase_from_file(args.passphrase_file),
                           private_dir / "intermediate.key.pem")
        save_certificate(int_cert, certs_dir / "intermediate.cert.pem")
        create_policy_file(out_dir, args.subject, serial_int, args.validity_days, args.key_type, args.key_size,
                           issuer=root_cert.subject.rfc4514_string())

        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="ca_init",
                status="success",
                message="Intermediate CA created successfully",
                metadata={"serial": serial_to_hex(serial_int), "subject": subject_name.rfc4514_string()}
            )
        logger.info("Intermediate CA creation completed.")

    except PolicyError as e:
        logger.error(f"Policy violation: {e}")
        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="ca_init",
                status="failure",
                message=f"Policy violation: {e}",
                metadata={"subject": args.subject}
            )
        raise
    except Exception as e:
        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="ca_init",
                status="failure",
                message=f"Error: {str(e)}",
                metadata={"subject": args.subject}
            )
        raise


# ==========================================
# БЛОК 4: Leaf Certificates (Sprint 2 + 6 CSR Support + 7 Policy)
# ==========================================

def issue_end_entity_cert(args, logger):
    logger.info(f"Starting certificate issuance (Template: {args.template})...")

    if hasattr(args, 'audit_logger'):
        args.audit_logger.audit(
            operation="issue_certificate",
            status="started",
            message=f"Issuing {args.template} certificate",
            metadata={"template": args.template, "subject": getattr(args, 'subject', 'from_csr')}
        )

    try:
        with open(args.ca_cert, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        ca_pass = read_passphrase_from_file(args.ca_pass_file)
        with open(args.ca_key, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=ca_pass, backend=default_backend())

        subject_name = None
        public_key = None
        san_list = []
        k_type = "rsa"

        # --- Sprint 6: Поддержка CSR ---
        if hasattr(args, 'csr') and args.csr:
            with open(args.csr, "rb") as f:
                csr = x509.load_pem_x509_csr(f.read())

            if not csr.is_signature_valid:
                raise ValueError("Invalid CSR signature.")

            # Проверка алгоритма подписи CSR
            check_signature_algorithm(csr, "rsa" if isinstance(csr.public_key(), rsa.RSAPublicKey) else "ecc")

            # Проверка на скомпрометированный ключ
            if is_key_compromised(getattr(args, 'db_path', './pki/micropki.db'), csr):
                raise PolicyError("CSR uses a compromised public key")

            public_key = csr.public_key()
            subject_name = csr.subject

            # Извлечение SAN из CSR
            try:
                san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san_list = list(san_ext.value)
            except x509.ExtensionNotFound:
                san_list = [parse_san_entry(s) for s in getattr(args, 'san', [])]

            if isinstance(public_key, ec.EllipticCurvePublicKey):
                k_type = "ecc"
            else:
                k_type = "rsa"

            logger.info("Using public key and subject from provided CSR.")
        else:
            # Старая логика генерации нового ключа
            subject_name = parse_subject_name(args.subject)
            if isinstance(ca_key, ec.EllipticCurvePrivateKey):
                leaf_key = ec.generate_private_key(ec.SECP256R1(), default_backend());
                k_type = "ecc"
            else:
                leaf_key = rsa.generate_private_key(65537, 2048, default_backend());
                k_type = "rsa"
            public_key = leaf_key.public_key()
            san_list = [parse_san_entry(s) for s in getattr(args, 'san', [])]

        # Проверки политик
        check_key_size(ca_key, "intermediate_ca", "rsa" if isinstance(ca_key, rsa.RSAPrivateKey) else "ecc")
        check_validity_period(args.validity_days, "end_entity")
        if san_list:
            check_san_policy(san_list, args.template)

        # Валидация шаблона и расширений
        try:
            extensions = get_template_extensions(args.template, san_list, k_type)
        except TemplateError as e:
            logger.error(f"Template validation failed: {e}")
            raise

        now = datetime.now(timezone.utc)
        serial_int = generate_unique_serial()

        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject_name).issuer_name(ca_cert.subject).public_key(public_key)
        cert_builder = cert_builder.serial_number(serial_int).not_valid_before(now).not_valid_after(
            now + timedelta(days=args.validity_days))

        for ext in extensions:
            cert_builder = cert_builder.add_extension(ext.value, critical=ext.critical)

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

        # Если ключ был сгенерирован нами (нет CSR), сохраняем его
        if not (hasattr(args, 'csr') and args.csr):
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

        # CT Log: добавляем запись о выпуске
        try:
            from .transparency import CTLog
            ct = CTLog(str(Path(args.out_dir).parent / "audit" / "ct.log"))
            ct.append(leaf_cert, ca_cert.subject.rfc4514_string())
        except Exception as e:
            logger.warning(f"Could not append to CT log: {e}")

        # Аудит успешного выпуска
        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="issue_certificate",
                status="success",
                message=f"Issued {args.template} certificate",
                metadata={
                    "serial": serial_to_hex(serial_int),
                    "subject": subject_name.rfc4514_string(),
                    "template": args.template
                }
            )

        logger.info(
            f"AUDIT: Issued {args.template} cert for {subject_name.rfc4514_string()} (Serial: {serial_to_hex(serial_int)})")
        logger.info("Certificate issuance completed.")
        return cert_pem_data

    except PolicyError as e:
        logger.error(f"Policy violation: {e}")
        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="issue_certificate",
                status="failure",
                message=f"Policy violation: {e}",
                metadata={"template": args.template, "subject": str(subject_name) if subject_name else "N/A"}
            )
        raise
    except Exception as e:
        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="issue_certificate",
                status="failure",
                message=f"Error: {str(e)}",
                metadata={"template": args.template}
            )
        raise


# ==========================================
# БЛОК 5: Sprint 4 (CRL) & Sprint 5 (OCSP Cert)
# ==========================================

def revoke_certificate(args, logger):
    """Отзыв сертификата по серийному номеру"""
    serial_hex = args.serial.upper()
    reason = args.reason if args.reason else "unspecified"
    db_path = getattr(args, 'db_path', "./pki/micropki.db")

    if hasattr(args, 'audit_logger'):
        args.audit_logger.audit(
            operation="revoke_certificate",
            status="started",
            message=f"Revoking certificate {serial_hex}",
            metadata={"serial": serial_hex, "reason": reason}
        )

    try:
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

        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="revoke_certificate",
                status="success",
                message=f"Certificate {serial_hex} revoked",
                metadata={"serial": serial_hex, "reason": reason}
            )

        logger.info(f"Certificate {serial_hex} successfully revoked. Reason: {reason}")
        logger.info("Run 'ca gen-crl' to update the CRL file.")

    except Exception as e:
        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="revoke_certificate",
                status="failure",
                message=f"Error: {str(e)}",
                metadata={"serial": serial_hex}
            )
        raise


def generate_crl_cli(args, logger):
    """Генерация файла CRL"""
    ca_level = args.ca.lower()
    next_update_days = args.next_update
    out_file = args.out_file
    db_path = getattr(args, 'db_path', "./pki/micropki.db")
    out_dir = Path(getattr(args, 'out_dir', "./pki"))

    if hasattr(args, 'audit_logger'):
        args.audit_logger.audit(
            operation="generate_crl",
            status="started",
            message=f"Generating CRL for {ca_level} CA",
            metadata={"ca_level": ca_level}
        )

    try:
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

        if not cert_path.exists(): raise FileNotFoundError(f"CA certificate not found: {cert_path}")
        with open(cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        if not key_path.exists(): raise FileNotFoundError(f"CA key not found: {key_path}")

        if not pass_arg:
            default_pass = out_dir.parent / "secrets" / ("root.pass" if ca_level == 'root' else "intermediate.pass")
            if default_pass.exists():
                pass_arg = str(default_pass)
            else:
                raise FileNotFoundError("Passphrase file not provided or found.")

        ca_pass = read_passphrase_from_file(pass_arg)
        with open(key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=ca_pass, backend=default_backend())

        revoked_list = get_revoked_certificates(db_path, issuer_dn=ca_cert.subject.rfc4514_string())
        logger.info(f"Found {len(revoked_list)} revoked certificates for {ca_level} CA.")

        meta = get_crl_metadata(db_path, ca_cert.subject.rfc4514_string())
        crl_num = (meta['crl_number'] + 1) if meta else 1

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

        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="generate_crl",
                status="success",
                message=f"CRL #{crl_num} generated for {ca_level} CA",
                metadata={"ca_level": ca_level, "crl_number": crl_num, "revoked_count": len(revoked_list)}
            )

        logger.info("CRL metadata updated in database.")

    except Exception as e:
        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="generate_crl",
                status="failure",
                message=f"Error: {str(e)}",
                metadata={"ca_level": ca_level}
            )
        raise


def issue_ocsp_cert(args, logger):
    """Выпуск сертификата для OCSP респондера (Sprint 5)"""
    logger.info("Issuing OCSP Responder Certificate...")

    if hasattr(args, 'audit_logger'):
        args.audit_logger.audit(
            operation="issue_ocsp_cert",
            status="started",
            message="Issuing OCSP responder certificate",
            metadata={"subject": args.subject}
        )

    try:
        with open(args.ca_cert, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        ca_pass = read_passphrase_from_file(args.ca_pass_file)
        with open(args.ca_key, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=ca_pass, backend=default_backend())

        subject_name = parse_subject_name(args.subject)

        # Генерация ключа
        if args.key_type == "rsa":
            key_size = args.key_size if args.key_size else 2048
            responder_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size,
                                                     backend=default_backend())
        elif args.key_type == "ecc":
            responder_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        else:
            raise ValueError("Unsupported key type")

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        key_path = out_dir / "ocsp.key.pem"
        key_pem = responder_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        key_path.write_bytes(key_pem)
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
        logger.warning(f"Unencrypted OCSP key saved to: {key_path}")

        now = datetime.now(timezone.utc)
        serial_int = generate_unique_serial()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject_name)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.public_key(responder_key.public_key())
        builder = builder.serial_number(serial_int)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(days=args.validity_days))

        # Basic Constraints: CA=FALSE
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

        # Key Usage: digitalSignature
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False),
            critical=True
        )

        # Extended Key Usage: OCSPSigning
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=True
        )

        # SAN
        if args.san:
            san_list = [parse_san_entry(s) for s in args.san]
            builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

        # AIA (опционально)
        aia_uri = None
        if args.san:
            for s in args.san:
                if s.startswith("uri:"):
                    aia_uri = s[4:]
                    break
        if aia_uri:
            builder = builder.add_extension(
                x509.AuthorityInformationAccess([
                    AccessDescription(AuthorityInformationAccessOID.OCSP, GeneralName(GeneralName.URI, aia_uri))
                ]),
                critical=False
            )

        sig_algo = hashes.SHA256() if isinstance(ca_key, rsa.RSAPrivateKey) else hashes.SHA384()
        cert = builder.sign(ca_key, sig_algo, default_backend())

        cert_path = out_dir / "ocsp.cert.pem"
        save_certificate(cert, cert_path)
        logger.info(f"OCSP Responder certificate saved: {cert_path}")

        db_path = getattr(args, 'db_path', None)
        if db_path:
            try:
                pem_data = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                add_certificate(db_path, serial_to_hex(serial_int), subject_name.rfc4514_string(),
                                ca_cert.subject.rfc4514_string(), cert.not_valid_before_utc, cert.not_valid_after_utc,
                                pem_data)
                logger.info("OCSP cert added to database.")
            except Exception as e:
                logger.warning(f"Could not add OCSP cert to DB: {e}")

        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="issue_ocsp_cert",
                status="success",
                message="OCSP responder certificate issued",
                metadata={"serial": serial_to_hex(serial_int), "subject": subject_name.rfc4514_string()}
            )

        logger.info("OCSP Responder certificate issuance completed.")

    except Exception as e:
        if hasattr(args, 'audit_logger'):
            args.audit_logger.audit(
                operation="issue_ocsp_cert",
                status="failure",
                message=f"Error: {str(e)}",
                metadata={"subject": args.subject}
            )
        raise