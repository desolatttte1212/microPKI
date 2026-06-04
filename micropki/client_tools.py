import os
import stat
import requests
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend

from .validation import build_chain, validate_path, ValidationError
from .revocation_check import check_revocation_status, get_ocsp_url


def gen_csr(args, logger):
    if args.key_type == 'rsa':
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=args.key_size, backend=default_backend())
    elif args.key_type == 'ecc':
        curve = ec.SECP256R1() if args.key_size == 256 else ec.SECP384R1()
        private_key = ec.generate_private_key(curve, backend=default_backend())

    key_path = Path(args.out_key)
    key_path.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    logger.warning(f"Unencrypted private key saved to: {key_path}")

    subject_attrs = []
    for part in args.subject.split(','):
        k, v = part.split('=')
        oid_map = {'CN': NameOID.COMMON_NAME, 'O': NameOID.ORGANIZATION_NAME}
        if k.strip() in oid_map:
            subject_attrs.append(x509.NameAttribute(oid_map[k.strip()], v.strip()))
    subject_name = x509.Name(subject_attrs)

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject_name)

    if args.san:
        san_list = []
        for s in args.san:
            if s.startswith('dns:'):
                san_list.append(x509.DNSName(s[4:]))
            elif s.startswith('ip:'):
                import ipaddress
                san_list.append(x509.IPAddress(ipaddress.ip_address(s[3:])))
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

    csr = builder.sign(private_key, hashes.SHA256(), default_backend())

    csr_path = Path(args.out_csr)
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    logger.info(f"CSR generated: {csr_path}")


def request_cert(args, logger):
    with open(args.csr, 'rb') as f:
        csr_pem = f.read()

    url = f"{args.ca_url.rstrip('/')}/request-cert"
    params = {'template': args.template}
    headers = {'Content-Type': 'application/x-pem-file'}

    try:
        resp = requests.post(url, data=csr_pem, params=params, headers=headers, timeout=10)
        resp.raise_for_status()

        cert_pem = resp.content
        out_path = Path(args.out_cert)
        out_path.write_bytes(cert_pem)
        logger.info(f"Certificate received and saved to: {out_path}")

    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to request certificate: {e}")
        raise


def validate_chain(args, logger):
    with open(args.cert, 'rb') as f:
        leaf_cert = x509.load_pem_x509_certificate(f.read())

    trusted_roots = []
    with open(args.trusted, 'rb') as f:
        trusted_roots.append(x509.load_pem_x509_certificate(f.read()))

    untrusted = []
    if args.untrusted:
        with open(args.untrusted, 'rb') as f:
            untrusted.append(x509.load_pem_x509_certificate(f.read()))

    try:
        chain = build_chain(leaf_cert, untrusted, trusted_roots)
        logger.info("Chain built successfully.")

        validate_path(chain)
        logger.info("Path validation PASSED (Signatures & Validity).")

        if args.mode == 'full':
            issuer_cert = chain[1] if len(chain) > 1 else trusted_roots[0]

            crl_data = None
            if args.crl:
                if args.crl.startswith('http'):
                    crl_data = requests.get(args.crl).content
                else:
                    with open(args.crl, 'rb') as f:
                        crl_data = f.read()

            ocsp_url = args.ocsp_url if hasattr(args, 'ocsp_url') else None

            rev_status = check_revocation_status(leaf_cert, issuer_cert, ocsp_url=ocsp_url, crl_data=crl_data)
            logger.info(f"Revocation Status: {rev_status['status']} (Source: {rev_status['source']})")

            if rev_status['status'] == 'revoked':
                logger.error("Validation FAILED: Certificate is REVOKED")
                return False

        logger.info("Validation SUCCESSFUL")
        return True

    except ValidationError as e:
        logger.error(f"Validation FAILED: {e.message}")
        return False
    except Exception as e:
        logger.error(f"Validation Error: {e}")
        return False