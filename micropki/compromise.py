from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def hash_public_key(cert: x509.Certificate) -> str:
    """Вычисляет SHA-256 хеш открытого ключа (для идентификации)."""
    pub_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pub_der).hexdigest()


def mark_compromised(db_path: str, serial_hex: str, reason: str, audit_logger) -> None:
    """Помечает сертификат как скомпрометированный в БД."""
    from .database import get_connection, get_certificate_by_serial

    cert = get_certificate_by_serial(db_path, serial_hex)
    if not cert:
        raise ValueError(f"Certificate {serial_hex} not found")

    # Загружаем сертификат для хеширования публичного ключа
    cert_obj = x509.load_pem_x509_certificate(cert['cert_pem'].encode())
    pub_key_hash = hash_public_key(cert_obj)

    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        # Обновляем статус сертификата
        cursor.execute(
            """UPDATE certificates 
               SET status = 'revoked', revocation_reason = ?, revocation_date = ?
               WHERE serial_hex = ?""",
            (reason, datetime.now(timezone.utc).isoformat(), serial_hex.lower())
        )

        # Добавляем запись в compromised_keys
        cursor.execute(
            """INSERT OR REPLACE INTO compromised_keys 
               (public_key_hash, certificate_serial, compromise_date, compromise_reason)
               VALUES (?, ?, ?, ?)""",
            (pub_key_hash, serial_hex.lower(), datetime.now(timezone.utc).isoformat(), reason)
        )

    # Аудит
    audit_logger.audit(
        operation="key_compromise",
        status="success",
        message=f"Marked certificate {serial_hex} as compromised",
        metadata={"serial": serial_hex, "reason": reason, "pub_key_hash": pub_key_hash[:16] + "..."}
    )


def is_key_compromised(db_path: str, cert: x509.Certificate) -> bool:
    """Проверяет, скомпрометирован ли ключ сертификата."""
    from .database import get_connection

    pub_key_hash = hash_public_key(cert)

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM compromised_keys WHERE public_key_hash = ?",
            (pub_key_hash,)
        )
        return cursor.fetchone() is not None