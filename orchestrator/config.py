"""
Athena runtime configuration (agentic approval policy + response cache).

Location: $ATHENA_CONFIG if set, else <repo>/config/athena.json. The file is optional; missing
keys take the fail-safe defaults below. Read on every call, so edits apply without a restart.

Environment overrides (take precedence over the file):
  ATHENA_CACHE_DIR   cache directory (relative paths resolve against the repo root)
  ATHENA_CACHE_TTL   cache TTL in seconds; 0 disables the cache
"""
import json
import os
from dataclasses import dataclass
from typing import FrozenSet

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG_PATH = os.path.join(BASE_DIR, "config", "athena.json")
DEFAULT_CACHE_DIR = os.path.join(BASE_DIR, "cache")
DEFAULT_CACHE_TTL_SECONDS = 3600


class ConfigError(Exception):
    """Configuration file is unreadable or has invalid values."""


@dataclass(frozen=True)
class AthenaConfig:
    trusted_callers: FrozenSet[str] = frozenset()
    medium_risk_requires_approval: bool = True
    cache_dir: str = DEFAULT_CACHE_DIR
    cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS


def config_path() -> str:
    return os.environ.get("ATHENA_CONFIG") or DEFAULT_CONFIG_PATH


def _resolve_dir(path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)


def load_config() -> AthenaConfig:
    path = config_path()
    raw = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError) as e:
            raise ConfigError(f"cannot read {path}: {e}") from e
        if not isinstance(raw, dict):
            raise ConfigError(f"{path}: top level must be an object")

    trusted = raw.get("trusted_callers", [])
    if not isinstance(trusted, list) or not all(isinstance(c, str) and c for c in trusted):
        raise ConfigError("trusted_callers must be a list of non-empty strings")

    approval = raw.get("medium_risk_requires_approval", True)
    if not isinstance(approval, bool):
        raise ConfigError("medium_risk_requires_approval must be true or false")

    cache = raw.get("cache", {})
    if not isinstance(cache, dict):
        raise ConfigError("cache must be an object")
    cache_dir = os.environ.get("ATHENA_CACHE_DIR") or cache.get("dir") or DEFAULT_CACHE_DIR
    if not isinstance(cache_dir, str):
        raise ConfigError("cache.dir must be a string")

    ttl_raw = os.environ.get("ATHENA_CACHE_TTL")
    if ttl_raw is not None:
        try:
            ttl = int(ttl_raw)
        except ValueError as e:
            raise ConfigError("ATHENA_CACHE_TTL must be an integer") from e
    else:
        ttl = cache.get("ttl_seconds", DEFAULT_CACHE_TTL_SECONDS)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0:
        raise ConfigError("cache TTL must be a non-negative integer")

    return AthenaConfig(
        trusted_callers=frozenset(trusted),
        medium_risk_requires_approval=approval,
        cache_dir=_resolve_dir(cache_dir),
        cache_ttl_seconds=ttl,
    )
