"""
On-disk response cache shared by ti_query and ti_lookup.

Key: (source, normalised indicator). One JSON file per key, named by SHA-256 of the key.
Only successful tool results are stored (including "not found" / "no result"); errors and
VirusTotal "pending" scans never are. Writes are atomic (temp file + os.replace).
A corrupt or unreadable entry is treated as a miss.
"""
import hashlib
import json
import os
import tempfile
import time
from typing import Any, Callable, Dict, Optional


def is_cacheable(data: Dict[str, Any]) -> bool:
    return isinstance(data, dict) and "error" not in data and data.get("status") != "pending"


class ResponseCache:
    def __init__(self, directory: str, ttl_seconds: int, clock: Optional[Callable[[], float]] = None):
        self.directory = directory
        self.ttl_seconds = ttl_seconds
        self.clock = clock or (lambda: time.time())  # looked up per call, so tests can control time

    @property
    def enabled(self) -> bool:
        return self.ttl_seconds > 0

    def _path(self, source: str, indicator: str) -> str:
        digest = hashlib.sha256(json.dumps([source, indicator]).encode("utf-8")).hexdigest()
        return os.path.join(self.directory, f"{digest}.json")

    def get(self, source: str, indicator: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        path = self._path(source, indicator)
        try:
            with open(path, "r", encoding="utf-8") as f:
                entry = json.load(f)
            if entry["source"] != source or entry["indicator"] != indicator:
                return None
            if self.clock() - float(entry["stored_at"]) >= self.ttl_seconds:
                return None
            data = entry["data"]
            return data if isinstance(data, dict) else None
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def put(self, source: str, indicator: str, data: Dict[str, Any]) -> bool:
        """Store a result. Never raises: a cache problem must not break a lookup."""
        if not self.enabled or not is_cacheable(data):
            return False
        entry = {"source": source, "indicator": indicator, "stored_at": self.clock(), "data": data}
        try:
            os.makedirs(self.directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
        except OSError:
            return False
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(entry, f)
            os.replace(tmp, self._path(source, indicator))
        except (OSError, TypeError, ValueError):  # TypeError/ValueError: data not JSON-serialisable
            try:
                os.remove(tmp)
            except OSError:
                pass
            return False
        return True
