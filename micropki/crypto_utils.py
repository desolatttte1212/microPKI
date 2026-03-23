from pathlib import Path


def read_passphrase_from_file(file_path: str) -> bytes:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Passphrase file not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    with open(path, 'rb') as f:
        content = f.read()

    content = content.rstrip(b'\r\n')

    if not content:
        raise ValueError("Passphrase file is empty.")

    return content


def get_public_key_bytes(public_key):
    from cryptography.hazmat.primitives import serialization

    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )