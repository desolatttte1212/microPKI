import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.exceptions import InvalidSignature


def load_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_key(path: str, passphrase: bytes):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=passphrase)


def main():
    base_dir = Path("./pki")
    cert_path = base_dir / "certs" / "ca.cert.pem"
    key_path = base_dir / "private" / "ca.key.pem"
    pass_path = Path("./secrets/ca.pass")

    print("=== MicroPKI Verification Suite (Sprint 1) ===\n")

    if not cert_path.exists() or not key_path.exists():
        print("[FAIL] Files missing!")
        return 1
    print("[OK] Files exist.")

    try:
        cert = load_cert(str(cert_path))
        passphrase = pass_path.read_bytes().rstrip(b'\r\n')
        private_key = load_key(str(key_path), passphrase)
        print("[OK] Certificate and Encrypted Key loaded successfully.")
    except Exception as e:
        print(f"[FAIL] Loading error: {e}")
        return 1

    try:
        if cert.subject != cert.issuer:
            print("[FAIL] Subject != Issuer (Not self-signed)")
            return 1
        from cryptography.hazmat.backends import default_backend
        print("[OK] Certificate structure valid (Subject == Issuer).")
    except Exception as e:
        print(f"[FAIL] Structure error: {e}")
        return 1
    try:
        message = b"MicroPKI Test Message"
        public_key = cert.public_key()

        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())

        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(message, ec.ECDSA(hashes.SHA384()))
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA384()))
        else:
            raise ValueError("Unknown key type")

        print("[OK] Private Key matches Certificate Public Key (Signature test passed).")
    except InvalidSignature:
        print("[FAIL] Key mismatch! Signature verification failed.")
        return 1
    except Exception as e:
        print(f"[FAIL] Signature test error: {e}")
        return 1

    print("[OK] Encrypted Key decryption successful (Correct passphrase).")

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if not bc.value.ca:
            print("[FAIL] BasicConstraints: CA is not TRUE")
            return 1
        if not bc.critical:
            print("[WARN] BasicConstraints should be critical")

        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if not ku.value.key_cert_sign or not ku.value.crl_sign:
            print("[FAIL] KeyUsage missing keyCertSign or cRLSign")
            return 1

        print("[OK] Extensions valid (BasicConstraints CA=TRUE, KeyUsage correct).")
    except Exception as e:
        print(f"[FAIL] Extension check error: {e}")
        return 1

    print("\n--- Certificate Info ---")
    print(f"Subject: {cert.subject.rfc4514_string()}")
    print(f"Issuer: {cert.issuer.rfc4514_string()}")
    print(f"Serial: {hex(cert.serial_number)}")
    print(f"Valid From: {cert.not_valid_before_utc}")
    print(f"Valid To: {cert.not_valid_after_utc}")
    print(f"Algorithm: {cert.signature_algorithm_oid._name}")

    print("\n=== All Tests Passed! Sprint 1 Complete. ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())