from __future__ import annotations
import json
import hashlib
import os
import fcntl
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List


class AuditLogger:
    """Аудит-логгер с криптографической целостностью (хеш-цепочка)."""

    def __init__(self, log_path: str, chain_path: Optional[str] = None):
        self.log_path = Path(log_path)
        self.chain_path = Path(chain_path) if chain_path else self.log_path.parent / "chain.dat"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = self._load_chain()

    def _load_chain(self) -> str:
        """Загружает последний хеш из chain.dat или возвращает нулевой."""
        if self.chain_path.exists():
            return self.chain_path.read_text().strip()
        return "0" * 64  # Нулевой хеш для первой записи

    def _save_chain(self, current_hash: str):
        """Сохраняет текущий хеш в chain.dat."""
        self.chain_path.write_text(current_hash)

    def _canonical_json(self, entry: Dict[str, Any]) -> str:
        """Создает каноническое JSON-представление (для хеширования)."""
        return json.dumps(entry, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

    def _compute_hash(self, entry: Dict[str, Any]) -> str:
        """Вычисляет SHA-256 хеш записи (без поля integrity.hash)."""
        entry_copy = entry.copy()
        if "integrity" in entry_copy and "hash" in entry_copy["integrity"]:
            del entry_copy["integrity"]["hash"]
        content = self._canonical_json(entry_copy)
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def log(self, level: str, operation: str, status: str, message: str,
            metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Создает и записывает аудиторскую запись с хеш-цепочкой."""
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

        entry = {
            "timestamp": timestamp,
            "level": level.upper(),
            "operation": operation,
            "status": status,
            "message": message,
            "metadata": metadata or {},
            "integrity": {
                "prev_hash": self._prev_hash
            }
        }

        entry["integrity"]["hash"] = self._compute_hash(entry)

        # Атомарная запись с блокировкой файла
        with open(self.log_path, 'a', encoding='utf-8') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(self._canonical_json(entry) + '\n')
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        self._prev_hash = entry["integrity"]["hash"]
        self._save_chain(self._prev_hash)

        return entry

    def audit(self, operation: str, status: str, message: str,
              metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Удобный метод для AUDIT-уровня."""
        return self.log("AUDIT", operation, status, message, metadata)

    def verify_chain(self) -> tuple[bool, Optional[int], Optional[str]]:
        """
        Проверяет целостность всей хеш-цепочки.
        Возвращает: (is_valid, first_bad_index, error_message)
        """
        if not self.log_path.exists():
            return True, None, None

        entries = []
        with open(self.log_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))

        if not entries:
            return True, None, None

        prev_hash = "0" * 64

        for idx, entry in enumerate(entries):
            # Проверяем prev_hash
            if entry.get("integrity", {}).get("prev_hash") != prev_hash:
                return False, idx, f"prev_hash mismatch at entry {idx}"

            # Пересчитываем хеш
            computed_hash = self._compute_hash(entry)
            stored_hash = entry.get("integrity", {}).get("hash")

            if computed_hash != stored_hash:
                return False, idx, f"hash mismatch at entry {idx}: computed={computed_hash}, stored={stored_hash}"

            prev_hash = stored_hash

        # Проверяем финальный хеш против chain.dat
        expected_final = self._load_chain()
        if prev_hash != expected_final:
            return False, len(entries), f"chain.dat mismatch: expected={expected_final}, computed={prev_hash}"

        return True, None, None