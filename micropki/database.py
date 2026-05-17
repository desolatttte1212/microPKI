import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'valid',
    revocation_reason TEXT,
    revocation_date TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS crl_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_subject TEXT NOT NULL,
    crl_number INTEGER NOT NULL DEFAULT 1,
    last_generated TEXT NOT NULL,
    next_update TEXT NOT NULL,
    crl_path TEXT
);

CREATE INDEX IF NOT EXISTS idx_serial ON certificates(serial_hex);
CREATE INDEX IF NOT EXISTS idx_status ON certificates(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ca_subject ON crl_metadata(ca_subject);
"""


def get_db_path(db_path: str = "./pki/micropki.db") -> Path:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def get_connection(db_path: str):
    conn = sqlite3.connect(str(get_db_path(db_path)))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def init_db(db_path: str = "./pki/micropki.db") -> bool:
    with get_connection(db_path) as conn:
        conn.executescript(DB_SCHEMA)
    return True


def add_certificate(
        db_path: str, serial_hex: str, subject: str, issuer: str,
        not_before: datetime, not_after: datetime, cert_pem: str, status: str = "valid"
) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    serial_normalized = serial_hex.lower()
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO certificates 
                   (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (serial_normalized, subject, issuer, not_before.isoformat(), not_after.isoformat(), cert_pem, status,
                 now_iso)
            )
        except sqlite3.IntegrityError as e:
            raise ValueError(f"Certificate with serial {serial_hex} already exists.") from e


def get_certificate_by_serial(db_path: str, serial_hex: str) -> Optional[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM certificates WHERE serial_hex = ?", (serial_hex.lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None


def list_certificates(db_path: str, status_filter: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    query = "SELECT serial_hex, subject, issuer, not_before, not_after, status, created_at FROM certificates"
    params = []
    if status_filter:
        query += " WHERE status = ?"
        params.append(status_filter)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]


def update_certificate_status(db_path: str, serial_hex: str, new_status: str, reason: Optional[str] = None) -> bool:
    now_iso = datetime.now(timezone.utc).isoformat()
    serial_normalized = serial_hex.lower()
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM certificates WHERE serial_hex = ?", (serial_normalized,))
        row = cursor.fetchone()
        if not row:
            return False
        if row[0] == 'revoked':
            return True 

        cursor.execute(
            """UPDATE certificates SET status = ?, revocation_reason = ?, revocation_date = ?
               WHERE serial_hex = ?""",
            (new_status, reason, now_iso if new_status == 'revoked' else None, serial_normalized)
        )
        return cursor.rowcount > 0


def get_revoked_certificates(db_path: str, issuer_dn: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT serial_hex, revocation_date, revocation_reason FROM certificates WHERE status = 'revoked'"
    params = []
    if issuer_dn:
        query += " AND issuer = ?"
        params.append(issuer_dn)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]


def get_crl_metadata(db_path: str, ca_subject: str) -> Optional[Dict[str, Any]]:
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM crl_metadata WHERE ca_subject = ?", (ca_subject,))
        row = cursor.fetchone()
        return dict(row) if row else None


def update_crl_metadata(db_path: str, ca_subject: str, crl_number: int, next_update: datetime, crl_path: str) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE crl_metadata SET crl_number = ?, last_generated = ?, next_update = ?, crl_path = ?
               WHERE ca_subject = ?""",
            (crl_number, now_iso, next_update.isoformat(), crl_path, ca_subject)
        )
        if cursor.rowcount == 0:
            cursor.execute(
                """INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
                   VALUES (?, ?, ?, ?, ?)""",
                (ca_subject, crl_number, now_iso, next_update.isoformat(), crl_path)
            )