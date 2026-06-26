"""License validation and caching for CloakBrowser Pro.

Handles license key resolution, server validation with local caching,
and Pro version checks.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from .config import get_cache_dir, get_platform_tag

logger = logging.getLogger("cloakbrowser")

VALIDATE_URL = "https://cloakbrowser.dev/api/license/validate"
PRO_VERSION_URL = "https://cloakbrowser.dev/api/download/version"

LICENSE_CACHE_TTL = 86400  # 24 hours
PRO_VERSION_CHECK_INTERVAL = 3600  # 1 hour


@dataclass
class LicenseInfo:
    valid: bool
    plan: str
    expires: str | None


def resolve_license_key(license_key: str | None = None) -> str | None:
    """Resolve the license key: explicit param > env var > file > None."""
    if license_key and license_key.strip():
        return license_key.strip()
    env_key = os.environ.get("CLOAKBROWSER_LICENSE_KEY", "").strip()
    if env_key:
        return env_key
    key_file = get_cache_dir() / "license.key"
    try:
        content = key_file.read_text().strip()
        if content:
            return content
    except OSError:
        pass
    return None


def validate_license(license_key: str) -> LicenseInfo | None:
    """Validate a license key with the CloakBrowser server.

    Checks a local file cache first (24h TTL). Falls back to stale
    cache if the server is unreachable.

    Returns LicenseInfo if validation succeeded, None on total failure.
    """
    cache_path = get_cache_dir() / ".license_cache"
    key_sha = hashlib.sha256(license_key.encode()).hexdigest()

    cached = _read_cache(cache_path, key_sha)
    if cached:
        return cached

    try:
        resp = httpx.post(
            VALIDATE_URL,
            json={"license_key": license_key},
            timeout=10.0,
        )
        resp.raise_for_status()
        data = resp.json()

        info = LicenseInfo(
            valid=data.get("valid", False),
            plan=data.get("plan", "solo"),
            expires=data.get("expires"),
        )

        if info.valid:
            _write_cache(cache_path, key_sha, info)
        return info

    except Exception as e:
        logger.warning("License validation request failed: %s", e)

        stale = _read_cache(cache_path, key_sha, ignore_ttl=True)
        if stale:
            logger.warning("Using cached license validation (server unreachable)")
            return stale

        return None


def get_pro_latest_version() -> str | None:
    """Get the latest Pro binary version from the server.

    Rate-limited to 1 call per hour via a marker file.
    """
    marker = get_cache_dir() / f".last_pro_version_check_{get_platform_tag()}"

    if marker.exists():
        try:
            age = time.time() - marker.stat().st_mtime
            if age < PRO_VERSION_CHECK_INTERVAL:
                content = marker.read_text().strip()
                return content if content else None
        except OSError:
            pass

    try:
        resp = httpx.get(
            PRO_VERSION_URL,
            headers={"X-Platform": get_platform_tag()},
            timeout=10.0,
        )
        resp.raise_for_status()
        version = resp.json().get("version")
        if not version:
            return None

        marker.parent.mkdir(parents=True, exist_ok=True)
        tmp = marker.with_suffix(".tmp")
        tmp.write_text(version)
        os.replace(str(tmp), str(marker))
        return version

    except Exception as e:
        logger.debug("Pro version check failed: %s", e)
        return None


def _read_cache(
    cache_path: Path, key_sha: str, ignore_ttl: bool = False
) -> LicenseInfo | None:
    """Read cached license validation if it exists and is fresh."""
    try:
        if not cache_path.exists():
            return None

        data = json.loads(cache_path.read_text())

        if data.get("key_sha256") != key_sha:
            return None

        if not ignore_ttl:
            validated_at = data.get("validated_at", 0)
            if time.time() - validated_at > LICENSE_CACHE_TTL:
                return None

        expires = data.get("expires")
        if expires:
            try:
                from datetime import datetime, timezone
                exp_dt = datetime.fromisoformat(expires)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if exp_dt < datetime.now(timezone.utc):
                    return LicenseInfo(valid=False, plan=data.get("plan", "solo"), expires=expires)
            except (ValueError, TypeError):
                pass

        return LicenseInfo(
            valid=data.get("valid", False),
            plan=data.get("plan", "solo"),
            expires=expires,
        )
    except (json.JSONDecodeError, OSError, KeyError, TypeError):
        # TypeError: a corrupted cache with a non-numeric validated_at. Treat any
        # unreadable cache as absent rather than crashing the caller.
        return None


def _write_cache(cache_path: Path, key_sha: str, info: LicenseInfo) -> None:
    """Write license validation result to local cache (atomic via tmp+rename)."""
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = cache_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps({
            "key_sha256": key_sha,
            "valid": info.valid,
            "plan": info.plan,
            "expires": info.expires,
            "validated_at": time.time(),
        }))
        os.replace(str(tmp_path), str(cache_path))
    except OSError as e:
        logger.debug("Failed to write license cache: %s", e)
