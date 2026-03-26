import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

# Схема базы данных
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

CREATE INDEX IF NOT EXISTS idx_serial ON certificates(serial_hex);
CREATE INDEX IF NOT EXISTS idx_status ON certificates(status);
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
    path = get_db_path(db_path)
    with get_connection(db_path) as conn:
        conn.executescript(DB_SCHEMA)
    return True


def add_certificate(
        db_path: str,
        serial_hex: str,
        subject: str,
        issuer: str,
        not_before: datetime,
        not_after: datetime,
        cert_pem: str,
        status: str = "valid"
) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    nb_iso = not_before.isoformat()
    na_iso = not_after.isoformat()

    serial_normalized = serial_hex.lower()

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO certificates 
                   (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (serial_normalized, subject, issuer, nb_iso, na_iso, cert_pem, status, now_iso)
            )
        except sqlite3.IntegrityError as e:
            raise ValueError(f"Certificate with serial {serial_hex} already exists in database.") from e


def get_certificate_by_serial(db_path: str, serial_hex: str) -> Optional[Dict[str, Any]]:
    serial_normalized = serial_hex.lower()

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM certificates WHERE serial_hex = ?", (serial_normalized,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def list_certificates(
        db_path: str,
        status_filter: Optional[str] = None,
        limit: int = 100
) -> List[Dict[str, Any]]:
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


def update_certificate_status(
        db_path: str,
        serial_hex: str,
        new_status: str,
        reason: Optional[str] = None
) -> bool:
    now_iso = datetime.now(timezone.utc).isoformat()
    serial_normalized = serial_hex.lower()

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE certificates 
               SET status = ?, revocation_reason = ?, revocation_date = ?
               WHERE serial_hex = ?""",
            (new_status, reason, now_iso if new_status == 'revoked' else None, serial_normalized)
        )
        return cursor.rowcount > 0