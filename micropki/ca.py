import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from .crypto_utils import read_passphrase_from_file, get_public_key_bytes


def generate_key_pair(key_type: str, key_size: int):
    if key_type == "rsa":
        if key_size != 4096:
            raise ValueError("RSA key size must be 4096")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
    elif key_type == "ecc":
        if key_size != 384:
            raise ValueError("ECC key size must be 384 (P-384)")
        private_key = ec.generate_private_key(
            ec.SECP384R1(),
            backend=default_backend()
        )
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
        }

        if oid_name in oid_map:
            attributes.append(x509.NameAttribute(oid_map[oid_name], value))

    return x509.Name(attributes)


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

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    )

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        ),
        critical=False
    )

    if isinstance(private_key, rsa.RSAPrivateKey):
        signature_algorithm = hashes.SHA256()
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature_algorithm = hashes.SHA384()
    else:
        raise ValueError("Unknown key type for signing")

    return builder.sign(private_key, signature_algorithm, default_backend())


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


def create_policy_file(out_dir: Path, subject: str, serial: int, validity_days: int, key_type: str, key_size: int):
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=validity_days)

    content = f"""MicroPKI Certificate Policy Document
CA Name: {subject}
Certificate Serial Number: {hex(serial)}
Validity Period: {now.strftime('%Y-%m-%d')} to {not_after.strftime('%Y-%m-%d')}
Key Algorithm: {key_type.upper()}
Key Size: {key_size} bits
Purpose: Root CA for MicroPKI demonstration
Policy Version: 1.0
Creation Date: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}
"""
    policy_path = out_dir / "policy.txt"
    policy_path.write_text(content, encoding='utf-8')


def initialize_ca(args, logger):
    logger.info("Starting Root CA initialization...")

    logger.info("Reading passphrase...")
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
    logger.info(f"Policy document saved to: {out_dir / 'policy.txt'}")

    logger.info("Root CA initialization completed successfully.")