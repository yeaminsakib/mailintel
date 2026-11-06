"""
core/scoring/mail_score.py
Score a mail that is stored in the database.

One place builds the inputs of :meth:`RiskScorer.score_email` from stored
data, so every screen (mail list, mail detail, graph) shows the same number:

* SPF / DKIM / DMARC results      -> ``auth_json``
* From / Reply-To                 -> ``headers_json``
* attachments (name, MIME type)   -> the ``attachments`` table
* IOC scores, including cached enrichment results (VirusTotal, AbuseIPDB, ...)
* URLs                            -> IOCs of type ``url``
* Return-Path mismatch, display-name spoof, subject lure wording -> flag columns
"""
from __future__ import annotations

import json
from typing import Any

from core.storage.database import Database

from .risk_score import EmailScore, RiskScorer


def _json_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def email_flag_inputs(email: dict[str, Any]) -> dict[str, Any]:
    """Keyword arguments for ``score_email`` taken from a stored mail's flag columns.

    Rows written before schema v2 have no flags and give "no flag set".
    """
    flags = _json_dict(email.get("flags_json"))
    return {
        "return_path_mismatch": bool(email.get("return_path_mismatch")),
        "display_name_spoof": bool(flags.get("display_name_spoof")),
        "subject_patterns": list(flags.get("subject_patterns") or []),
    }


def score_stored_email(
    scorer: RiskScorer,
    email: dict[str, Any],
    iocs: list[dict[str, Any]],
    attachments: list[dict[str, Any]],
    enrichments_by_ioc: dict[int, list[dict[str, Any]]] | None = None,
) -> EmailScore:
    """Score one stored mail from rows already loaded from the database."""
    headers = _json_dict(email.get("headers_json"))
    auth = _json_dict(email.get("auth_json"))
    enrichments_by_ioc = enrichments_by_ioc or {}

    ioc_scores = {}
    for ioc in iocs:
        ioc_scores[ioc["value"]] = scorer.score_ioc(
            ioc_type=ioc["type"],
            ioc_value=ioc["value"],
            enrichment_results=enrichments_by_ioc.get(ioc["id"]),
            frequency=int(ioc.get("frequency") or 1),
        )

    return scorer.score_email(
        auth_results={key: str(auth.get(key, "none")) for key in ("spf", "dkim", "dmarc")},
        from_addr=headers.get("from_addr") or email.get("from_addr", ""),
        reply_to=headers.get("reply_to", ""),
        attachments=[
            {"filename": a.get("filename", ""), "mime_type": a.get("mime_type", "")}
            for a in attachments
        ],
        ioc_scores=ioc_scores,
        urls=[i["value"] for i in iocs if i["type"] == "url"],
        **email_flag_inputs(email),
    )


def score_emails(
    scorer: RiskScorer,
    db: Database,
    emails: list[dict[str, Any]],
) -> dict[int, EmailScore]:
    """Score many stored mails with a handful of queries (not one per mail)."""
    ids = [int(e["id"]) for e in emails]
    iocs_by_email: dict[int, list[dict[str, Any]]] = {}
    for start in range(0, len(ids), 500):
        iocs_by_email.update(db.get_iocs_for_emails(ids[start:start + 500]))
    attachments_by_email = db.get_attachments_for_emails(ids)

    enrichments: dict[int, list[dict[str, Any]]] = {}
    for rows in iocs_by_email.values():
        for ioc in rows:
            if ioc["id"] not in enrichments:
                enrichments[ioc["id"]] = db.get_enrichments_for_ioc(ioc["id"])

    return {
        int(e["id"]): score_stored_email(
            scorer,
            e,
            iocs_by_email.get(int(e["id"]), []),
            attachments_by_email.get(int(e["id"]), []),
            enrichments,
        )
        for e in emails
    }
