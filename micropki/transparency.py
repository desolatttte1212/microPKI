from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from pathlib import Path


class CTLog:
    """Простой симулятор лога Certificate Transparency."""

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, cert: 'x509.Certificate', issuer_dn: str = None):
        """Добавляет запись о сертификате в лог."""
        from cryptography.hazmat.primitives import hashes

        # Исправлено: используем hashes.SHA256() вместо hashlib.sha256()
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        serial_hex = f"{cert.serial_number:X}"
        subject_dn = cert.subject.rfc4514_string()
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

        entry = f"{timestamp}|{serial_hex}|{subject_dn}|{fingerprint}"
        if issuer_dn:
            entry += f"|{issuer_dn}"
        entry += '\n'

        with open(self.log_path, 'a', encoding='utf-8') as f:
            f.write(entry)

    def contains(self, serial_hex: str) -> bool:
        """Проверяет, есть ли сертификат с данным серийным номером в логе."""
        if not self.log_path.exists():
            return False
        with open(self.log_path, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) >= 2 and parts[1].upper() == serial_hex.upper():
                    return True
        return False