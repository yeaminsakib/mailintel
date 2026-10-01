"""
core/enrichment/keys.py
Secure API key management via the OS keyring.

Keys are stored and retrieved through the ``keyring`` library, which uses:
- **Windows**: Windows Credential Manager
- **macOS**: macOS Keychain
- **Linux**: Secret Service API (GNOME Keyring / KDE Wallet)

The service name is always ``"mailintel"`` so all credentials are grouped
under a single application namespace.

Usage::

    from core.enrichment.keys import get_api_key, set_api_key, delete_api_key

    set_api_key("virustotal", "abc123...")
    key = get_api_key("virustotal")       # -> "abc123..." or None
    delete_api_key("virustotal")
"""
from __future__ import annotations

import logging

import keyring
from keyring.errors import KeyringError

logger = logging.getLogger(__name__)

_SERVICE_NAME: str = "mailintel"


def get_api_key(provider: str) -> str | None:
    """Retrieve the API key for *provider* from the OS keyring.

    Returns ``None`` if no key is stored or the keyring is unavailable.
    """
    try:
        value = keyring.get_password(_SERVICE_NAME, provider)
        return value if value else None
    except KeyringError as exc:
        logger.warning("Keyring read failed for %s: %s", provider, exc)
        return None


def set_api_key(provider: str, api_key: str) -> bool:
    """Store an API key for *provider* in the OS keyring.

    Returns ``True`` on success, ``False`` on failure.
    """
    try:
        keyring.set_password(_SERVICE_NAME, provider, api_key)
        return True
    except KeyringError as exc:
        logger.error("Keyring write failed for %s: %s", provider, exc)
        return False


def delete_api_key(provider: str) -> bool:
    """Remove the API key for *provider* from the OS keyring.

    Returns ``True`` on success, ``False`` if the key didn't exist or
    the keyring is unavailable.
    """
    try:
        keyring.delete_password(_SERVICE_NAME, provider)
        return True
    except KeyringError as exc:
        logger.warning("Keyring delete failed for %s: %s", provider, exc)
        return False
