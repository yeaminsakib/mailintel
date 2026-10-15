"""
core/export/misp_exporter.py
Exports IOCs and threat attributes to a MISP-compatible event JSON package.
Format complies with standard MISP 2.4 Event schema with typed Attributes,
Threat Levels, Tags, and Galaxies.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Mapping from MailIntel internal IOC types to standard MISP attribute types
MISP_TYPE_MAP = {
    "ipv4": ("ip-dst", "Network activity"),
    "ipv6": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "url": ("url", "Network activity"),
    "email": ("email-src", "Payload delivery"),
    "hash_md5": ("md5", "Payload delivery"),
    "hash_sha1": ("sha1", "Payload delivery"),
    "hash_sha256": ("sha256", "Payload delivery"),
}

THREAT_LEVEL_MAP = {
    "CRITICAL": 1,  # High
    "HIGH": 2,      # Medium
    "MEDIUM": 3,    # Low
    "LOW": 4,       # Undefined
}


class MispExporter:
    """Exports correlated indicators and incident events to MISP JSON format."""

    def __init__(self, org_name: str = "MailIntel DFIR Lab") -> None:
        self.org_name = org_name

    def build_event(
        self,
        iocs: list[dict[str, Any]],
        emails: list[dict[str, Any]] | None = None,
        event_info: str = "MailIntel Email Threat Investigation",
        threat_level_id: int = 2,
        analysis: int = 2,  # 2 = Completed
        distribution: int = 0,  # 0 = Your organization only
    ) -> dict[str, Any]:
        """Construct a full MISP Event structure containing attributes and metadata.

        Parameters
        ----------
        iocs : list[dict[str, Any]]
            List of IOC dicts.
        emails : list[dict[str, Any]] | None
            Optional list of email records.
        event_info : str
            Title / info summary for the MISP event.
        threat_level_id : int
            MISP threat level: 1 (High), 2 (Medium), 3 (Low), 4 (Undefined).
        analysis : int
            MISP analysis stage: 0 (Initial), 1 (Ongoing), 2 (Completed).
        distribution : int
            MISP distribution flag.

        Returns
        -------
        dict[str, Any]
            Dict matching {"Event": {...}} schema.
        """
        now = datetime.now(timezone.utc)
        event_uuid = str(uuid.uuid4())
        org_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, self.org_name.lower().replace(" ", "")))
        event_date = now.strftime("%Y-%m-%d")

        attributes: list[dict[str, Any]] = []

        # 1. Convert IOCs to MISP Attributes
        for ioc in iocs:
            itype = ioc.get("type", "").lower()
            val = (ioc.get("value") or "").strip()
            if not val or itype not in MISP_TYPE_MAP:
                continue

            misp_type, misp_category = MISP_TYPE_MAP[itype]
            attr_uuid = str(uuid.uuid4())
            freq = int(ioc.get("frequency") or 1)

            attr = {
                "uuid": attr_uuid,
                "type": misp_type,
                "category": misp_category,
                "to_ids": True,
                "value": val,
                "comment": f"Observed in email corpus ({freq}x)",
                "timestamp": str(int(now.timestamp())),
                "distribution": "5",  # Inherit event
                "Tag": [
                    {"name": f"mailintel:type=\"{itype}\""},
                    {"name": "tlp:amber"},
                ],
            }
            attributes.append(attr)

        # 2. Add Email Header attributes if provided
        if emails:
            for em in emails:
                file_sha256 = em.get("file_sha256", "")
                filename = em.get("filename", "")
                headers = {}
                if isinstance(em.get("headers_json"), str):
                    try:
                        headers = json.loads(em["headers_json"] or "{}")
                    except Exception:
                        pass
                elif isinstance(em.get("headers_json"), dict):
                    headers = em["headers_json"]

                subject = headers.get("subject", "")
                from_addr = headers.get("from_addr", "")

                if file_sha256:
                    attributes.append({
                        "uuid": str(uuid.uuid4()),
                        "type": "sha256",
                        "category": "Payload delivery",
                        "to_ids": True,
                        "value": file_sha256,
                        "comment": f"EML Message Body/Attachment: {filename}",
                        "timestamp": str(int(now.timestamp())),
                        "Tag": [{"name": "mailintel:source=\"eml_hash\""}],
                    })
                if subject:
                    attributes.append({
                        "uuid": str(uuid.uuid4()),
                        "type": "email-subject",
                        "category": "Payload delivery",
                        "to_ids": False,
                        "value": subject,
                        "comment": f"Phishing subject from {filename}",
                        "timestamp": str(int(now.timestamp())),
                        "Tag": [{"name": "mailintel:source=\"email_subject\""}],
                    })
                if from_addr:
                    attributes.append({
                        "uuid": str(uuid.uuid4()),
                        "type": "email-src",
                        "category": "Payload delivery",
                        "to_ids": True,
                        "value": from_addr,
                        "comment": f"Header sender from {filename}",
                        "timestamp": str(int(now.timestamp())),
                        "Tag": [{"name": "mailintel:source=\"email_from\""}],
                    })

        event_dict: dict[str, Any] = {
            "Event": {
                "uuid": event_uuid,
                "org_id": "1",
                "orgc_id": "1",
                "Org": {"name": self.org_name, "uuid": org_uuid},
                "Orgc": {"name": self.org_name, "uuid": org_uuid},
                "info": event_info,
                "date": event_date,
                "threat_level_id": str(threat_level_id),
                "analysis": str(analysis),
                "distribution": str(distribution),
                "published": False,
                "timestamp": str(int(now.timestamp())),
                "Attribute": attributes,
                "Tag": [
                    {"name": "tlp:amber"},
                    {"name": "misp-galaxy:threat-actor=\"Phishing Campaign\""},
                    {"name": "mailintel:confidence=\"high\""},
                ],
            }
        }
        return event_dict

    def export_to_file(
        self,
        filepath: str | Path,
        iocs: list[dict[str, Any]],
        emails: list[dict[str, Any]] | None = None,
        event_info: str = "MailIntel Email Threat Investigation",
        indent: int = 2,
    ) -> Path:
        """Serialize MISP event JSON directly to disk."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        event_data = self.build_event(iocs=iocs, emails=emails, event_info=event_info)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(event_data, fh, indent=indent, ensure_ascii=False)
        return path
