"""
core/export/stix_exporter.py
Exports IOCs and parsed emails to an OASIS STIX 2.1 JSON bundle using the stix2 library.
Generates Indicator, ObservedData, and Relationship SDOs/SROs.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import stix2

from core.ioc.defang import defang

logger = logging.getLogger(__name__)


def _to_stix_timestamp(ts: Any) -> datetime:
    """Parse or format a timestamp to a UTC datetime suitable for stix2."""
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, str) and ts.strip():
        try:
            # Handle ISO formats
            clean = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _stix_pattern_for_ioc(ioc_type: str, value: str) -> tuple[str, dict[str, Any]] | None:
    """Return the STIX 2.1 comparison pattern string and SCO representation."""
    cleaned_val = value.strip().replace("'", "\\'")
    itype = ioc_type.lower()

    if itype in ("ipv4", "ipv6"):
        pattern = f"[ipv4-addr:value = '{cleaned_val}']" if itype == "ipv4" else f"[ipv6-addr:value = '{cleaned_val}']"
        sco = {"type": f"{itype}-addr", "value": value}
        return pattern, sco
    elif itype == "domain":
        pattern = f"[domain-name:value = '{cleaned_val}']"
        sco = {"type": "domain-name", "value": value}
        return pattern, sco
    elif itype == "url":
        pattern = f"[url:value = '{cleaned_val}']"
        sco = {"type": "url", "value": value}
        return pattern, sco
    elif itype == "email":
        pattern = f"[email-addr:value = '{cleaned_val}']"
        sco = {"type": "email-addr", "value": value}
        return pattern, sco
    elif itype == "hash_md5":
        pattern = f"[file:hashes.MD5 = '{cleaned_val}']"
        sco_file: dict[str, Any] = {"type": "file", "hashes": {"MD5": value}}
        return pattern, sco_file
    elif itype == "hash_sha1":
        pattern = f"[file:hashes.'SHA-1' = '{cleaned_val}']"
        sco_sha1: dict[str, Any] = {"type": "file", "hashes": {"SHA-1": value}}
        return pattern, sco_sha1
    elif itype == "hash_sha256":
        pattern = f"[file:hashes.'SHA-256' = '{cleaned_val}']"
        sco_sha256: dict[str, Any] = {"type": "file", "hashes": {"SHA-256": value}}
        return pattern, sco_sha256
    return None


class StixExporter:
    """Exports threat indicators and observation telemetry to a STIX 2.1 Bundle."""

    def __init__(self, confidence_score: int = 80) -> None:
        self.confidence_score = confidence_score

    def build_bundle(
        self,
        iocs: list[dict[str, Any]],
        emails: list[dict[str, Any]] | None = None,
        description: str = "MailIntel Threat Intelligence Extraction",
    ) -> stix2.Bundle:
        """Construct a STIX 2.1 Bundle containing Indicators, ObservedData, and Relationships.

        Parameters
        ----------
        iocs : list[dict[str, Any]]
            List of IOC records (must contain 'type' and 'value').
        emails : list[dict[str, Any]] | None
            Optional list of email records for context and observed telemetry.
        description : str
            Bundle description summary.

        Returns
        -------
        stix2.Bundle
            Serialized STIX 2.1 bundle object.
        """
        objects: list[Any] = []

        # 1. Identity representing MailIntel analyst engine
        identity = stix2.Identity(
            name="MailIntel Automated DFIR Engine",
            identity_class="system",
            description="Automated email threat intelligence analysis and DFIR extractor",
        )
        objects.append(identity)

        # Map to track created indicators and observed-data
        indicator_map: dict[str, stix2.Indicator] = {}

        for ioc in iocs:
            itype = ioc.get("type", "")
            val = ioc.get("value", "")
            if not itype or not val:
                continue

            pat_res = _stix_pattern_for_ioc(itype, val)
            if not pat_res:
                continue
            pattern_str, sco_dict = pat_res

            freq = int(ioc.get("frequency") or 1)
            first_seen = _to_stix_timestamp(ioc.get("first_seen"))
            last_seen = _to_stix_timestamp(ioc.get("last_seen"))

            # Create STIX 2.1 Indicator
            ind_name = f"Malicious {itype.upper()}: {defang(val)}"
            ind = stix2.Indicator(
                name=ind_name,
                description=f"Extracted by MailIntel. Observed frequency across corpus: {freq}",
                pattern=pattern_str,
                pattern_type="stix",
                valid_from=first_seen,
                confidence=self.confidence_score,
                created_by_ref=identity.id,
                labels=["malicious-activity", f"mailintel-{itype}"],
            )
            objects.append(ind)
            indicator_map[f"{itype}:{val}"] = ind

            # Create STIX 2.1 ObservedData
            obs = stix2.ObservedData(
                first_observed=first_seen,
                last_observed=last_seen,
                number_observed=freq,
                objects={"0": sco_dict},
                created_by_ref=identity.id,
            )
            objects.append(obs)

            # Create STIX 2.1 Relationship (indicator based-on observed-data)
            rel = stix2.Relationship(
                source_ref=ind.id,
                target_ref=obs.id,
                relationship_type="based-on",
                description=f"Indicator {ind.name} derived from ObservedData {obs.id}",
            )
            objects.append(rel)

        # 2. Email messages as ObservedData (if email records provided)
        if emails:
            for email in emails:
                file_sha256 = email.get("file_sha256", "")
                filename = email.get("filename", "unknown.eml")
                first_seen = _to_stix_timestamp(email.get("first_seen"))

                headers = {}
                if isinstance(email.get("headers_json"), str):
                    try:
                        headers = json.loads(email["headers_json"] or "{}")
                    except Exception:
                        pass
                elif isinstance(email.get("headers_json"), dict):
                    headers = email["headers_json"]

                subject = headers.get("subject", "") or filename
                from_addr = headers.get("from_addr", "")

                email_sco: dict[str, Any] = {
                    "type": "email-message",
                    "is_multipart": True,
                    "subject": subject,
                }
                sco_objects: dict[str, Any] = {"0": email_sco}
                if from_addr:
                    sco_objects["1"] = {"type": "email-addr", "value": from_addr}
                if file_sha256:
                    sco_objects["2"] = {"type": "file", "hashes": {"SHA-256": file_sha256}, "name": filename}

                email_obs = stix2.ObservedData(
                    first_observed=first_seen,
                    last_observed=first_seen,
                    number_observed=1,
                    objects=sco_objects,
                    created_by_ref=identity.id,
                )
                objects.append(email_obs)

        bundle = stix2.Bundle(objects=objects, allow_custom=True)
        return bundle

    def export_to_file(
        self,
        filepath: str | Path,
        iocs: list[dict[str, Any]],
        emails: list[dict[str, Any]] | None = None,
        pretty: bool = True,
    ) -> Path:
        """Serialize STIX 2.1 bundle directly to disk."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        bundle = self.build_bundle(iocs=iocs, emails=emails)
        raw_json = bundle.serialize(pretty=pretty)
        path.write_text(raw_json, encoding="utf-8")
        return path
