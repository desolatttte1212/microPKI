import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def load_pem(path):
    with open(path, "rb") as f:
        data = f.read()
        try:
            return x509.load_pem_x509_certificate(data, default_backend())
        except ValueError:
            raise ValueError(f"Failed to load certificate from {path}")


def get_hash_algorithm(cert):
    oid = cert.signature_algorithm_oid._name

    if 'sha256' in oid.lower():
        return hashes.SHA256()
    elif 'sha384' in oid.lower():
        return hashes.SHA384()
    elif 'sha512' in oid.lower():
        return hashes.SHA512()
    elif 'sha1' in oid.lower():
        return hashes.SHA1()
    else:
        return hashes.SHA256()


def verify_signature(cert, issuer_cert):
    try:
        issuer_public_key = issuer_cert.public_key()
        hash_algo = get_hash_algorithm(cert)

        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_algo
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(hash_algo)
            )
        else:
            print(f"Unsupported key type: {type(issuer_public_key)}")
            return False

        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Error during verification: {e}")
        return False


def check_validity(cert):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    try:
        start = cert.not_valid_before_utc
        end = cert.not_valid_after_utc
    except AttributeError:
        start = cert.not_valid_before
        end = cert.not_valid_after

    if start <= now <= end:
        return True
    return False


def main():
    base_dir = Path("./pki")
    root_path = base_dir / "certs" / "ca.cert.pem"
    int_path = base_dir / "certs" / "intermediate.cert.pem"
    leaf_path = base_dir / "certs" / "issued" / "example.com.cert.pem"

    print("=== MicroPKI Chain Verification (Sprint 2) ===\n")

    try:
        root_cert = load_pem(root_path)
        int_cert = load_pem(int_path)
        leaf_cert = load_pem(leaf_path)
        print("[OK] All certificates loaded successfully.")
    except Exception as e:
        print(f"[FAIL] Error loading certificates: {e}")
        return 1

    if verify_signature(leaf_cert, int_cert):
        print("[OK] Leaf certificate is correctly signed by Intermediate CA.")
    else:
        print("[FAIL] Leaf certificate signature INVALID!")
        return 1

    if verify_signature(int_cert, root_cert):
        print("[OK] Intermediate CA is correctly signed by Root CA.")
    else:
        print("[FAIL] Intermediate CA signature INVALID!")
        return 1

    if verify_signature(root_cert, root_cert):
        print("[OK] Root CA is self-signed correctly.")
    else:
        print("[FAIL] Root CA self-signature INVALID!")
        return 1

    if check_validity(root_cert) and check_validity(int_cert) and check_validity(leaf_cert):
        print("[OK] All certificates are within their validity period.")
    else:
        print("[WARN] One or more certificates are expired or not yet valid.")

    try:
        bc_leaf = leaf_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc_leaf.ca:
            print("[FAIL] Leaf certificate has CA=TRUE (should be FALSE)!")
            return 1
        print("[OK] Leaf certificate BasicConstraints are correct (CA=FALSE).")
    except Exception as e:
        print(f"[FAIL] Error checking Leaf extensions: {e}")
        return 1

    try:
        bc_int = int_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not bc_int.ca:
            print("[FAIL] Intermediate CA has CA=FALSE (should be TRUE)!")
            return 1
        print(f"[OK] Intermediate CA BasicConstraints are correct (CA=TRUE, PathLen={bc_int.path_length}).")
    except Exception as e:
        print(f"[FAIL] Error checking Intermediate extensions: {e}")
        return 1

    try:
        san_ext = leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = [name.value for name in san_ext if isinstance(name, x509.DNSName)]
        ip_names = [str(name.value) for name in san_ext if isinstance(name, x509.IPAddress)]
        print(f"[OK] Leaf certificate SANs found: DNS={dns_names}, IP={ip_names}")
    except Exception as e:
        print(f"[FAIL] Error checking SANs: {e}")
        return 1

    print("\n=== ✅ CHAIN VALIDATION SUCCESSFUL ===")
    print("Trust Chain: Root CA -> Intermediate CA -> example.com")
    return 0


if __name__ == "__main__":
    sys.exit(main())