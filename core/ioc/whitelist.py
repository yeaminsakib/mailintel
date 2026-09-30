"""
core/ioc/whitelist.py
Context-aware whitelist for IOC filtering.

Whitelists are loaded from ``data/whitelist.yaml`` and keyed by context:

- ``infrastructure``: domains in Received headers / mail relay chains
- ``body_url``: domains in body URLs (much stricter — no cloud providers)
- ``sender``: sender email domains (free-mail providers)
- ``artifacts``: encoding strings that regex may match as domains

A domain whitelisted in ``infrastructure`` is **not** trusted in
``body_url``.  Attackers routinely abuse cloud provider domains.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# Fallback when YAML file is missing or PyYAML not installed
_DEFAULT_WHITELIST: dict[str, dict[str, list[str]]] = {
    "infrastructure": {
        "domains": [
            "google.com", "googleapis.com", "googleusercontent.com",
            "gstatic.com", "microsoft.com", "microsoftonline.com",
            "office.com", "office365.com", "outlook.com",
            "live.com", "hotmail.com", "windows.com",
            "apple.com", "icloud.com",
            "spf.protection.outlook.com",
            "cloudflare.com", "cloudflare-dns.com",
            "akamaiedge.net", "fastly.net",
            "sendgrid.net", "mailchimp.com", "mailgun.org",
            "amazonses.com", "smtp.gmail.com", "mail.google.com",
        ],
    },
    "body_url": {
        "domains": [
            "w3.org", "iana.org", "ietf.org", "rfc-editor.org",
            "schemas.microsoft.com", "schemas.openxmlformats.org",
        ],
    },
    "sender": {
        "domains": [
            "gmail.com", "outlook.com", "yahoo.com",
            "hotmail.com", "live.com", "icloud.com",
        ],
    },
    "artifacts": {
        "patterns": ["utf-8", "charset", "iso-8859-1", "us-ascii"],
    },
}


class WhitelistPolicy:
    """Context-aware whitelist policy.

    Usage::

        policy = WhitelistPolicy.load()

        # Infrastructure context — sendgrid.net IS whitelisted
        policy.is_whitelisted("sendgrid.net", context="infrastructure")  # True

        # Body URL context — sendgrid.net is NOT whitelisted (abused by attackers)
        policy.is_whitelisted("sendgrid.net", context="body_url")  # False
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._cache: dict[str, set[str]] = {}

        for context_name, context_data in config.items():
            if isinstance(context_data, dict):
                domains = context_data.get("domains", [])
                self._cache[context_name] = {
                    d.lower().strip(".") for d in domains
                }

    @classmethod
    def load(cls, yaml_path: str | Path | None = None) -> WhitelistPolicy:
        """Load whitelist from YAML.

        Falls back to built-in defaults if the file is missing or
        ``PyYAML`` is not installed.
        """
        if yaml_path is None:
            project_root = Path(__file__).resolve().parent.parent.parent
            yaml_path = project_root / "data" / "whitelist.yaml"

        yaml_path = Path(yaml_path)

        if _HAS_YAML and yaml_path.is_file():
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f) or {}
                return cls(config)
            except Exception:
                pass

        return cls(_DEFAULT_WHITELIST)

    def is_whitelisted(self, domain: str, context: str = "body_url") -> bool:
        """Check if *domain* (or a parent zone) is whitelisted in *context*.

        Parameters
        ----------
        domain : str
            Domain to check (e.g. ``'sub.google.com'``).
        context : str
            ``'infrastructure'``, ``'body_url'``, ``'sender'``, or
            ``'artifacts'``.

        Returns
        -------
        bool
        """
        d = domain.lower().strip(".")
        domain_set = self._cache.get(context, set())

        # Direct match
        if d in domain_set:
            return True

        # Parent-zone walk (sub.google.com → google.com)
        parts = d.split(".")
        for i in range(1, len(parts) - 1):  # keep ≥ 2 labels
            parent = ".".join(parts[i:])
            if parent in domain_set:
                return True

        # Check artifacts (encoding strings that look like domains)
        artifacts_data = self._config.get("artifacts", {})
        if isinstance(artifacts_data, dict):
            patterns = artifacts_data.get("patterns", [])
            if d in [p.lower() for p in patterns]:
                return True

        return False

    def get_domains(self, context: str) -> set[str]:
        """Return the set of whitelisted domains for a context."""
        return self._cache.get(context, set()).copy()
