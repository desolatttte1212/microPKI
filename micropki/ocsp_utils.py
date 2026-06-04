import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import Name

def compute_issuer_name_hash(issuer_name: Name) -> str:
    return hashlib.sha1(issuer_name.public_bytes()).hexdigest().upper()

def compute_issuer_key_hash(issuer_public_key) -> str:
    pub_bytes = issuer_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha1(pub_bytes).hexdigest().upper()