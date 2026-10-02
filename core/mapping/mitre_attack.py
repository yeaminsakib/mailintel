"""
core/mapping/mitre_attack.py
Map observed behaviours to MITRE ATT&CK technique IDs.

The mapping data lives in ``data/mitre_map.yaml``.  This module loads
it once and exposes a simple lookup API.

Public API
----------
MitreMapper
    Load ``mitre_map.yaml`` and look up techniques by behaviour tag.
Technique
    Dataclass representing a single ATT&CK technique.

Usage::

    mapper = MitreMapper()
    techniques = mapper.lookup(["phishing_attachment", "spf_failure"])
    for t in techniques:
        print(f"{t.technique_id} — {t.name} ({t.tactic})")
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DATA_DIR: Path = Path(__file__).resolve().parent.parent.parent / "data"


@dataclass(frozen=True)
class Technique:
    """A single MITRE ATT&CK technique.

    Attributes
    ----------
    technique_id : str
        E.g. ``'T1566.001'``.
    name : str
        Human-readable name.
    tactic : str
        ATT&CK tactic (e.g. ``'Initial Access'``).
    description : str
        Short explanation of relevance.
    behaviour_tag : str
        The behaviour tag that triggered this mapping.
    """

    technique_id: str
    name: str
    tactic: str
    description: str
    behaviour_tag: str


class MitreMapper:
    """Look up MITRE ATT&CK techniques from behaviour tags.

    Parameters
    ----------
    yaml_path : Path or None
        Override path to ``mitre_map.yaml``.
    """

    def __init__(self, yaml_path: Path | None = None) -> None:
        self._map: dict[str, dict[str, Any]] = {}
        self._load(yaml_path)

    def _load(self, path: Path | None) -> None:
        """Load the YAML mapping file."""
        if path is None:
            path = _DATA_DIR / "mitre_map.yaml"
        if not path.is_file():
            logger.warning("MITRE map not found: %s", path)
            return
        try:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if isinstance(data, dict):
                self._map = data
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load MITRE map: %s", exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup(self, behaviour_tags: list[str]) -> list[Technique]:
        """Return all matching ATT&CK techniques for the given tags.

        Parameters
        ----------
        behaviour_tags : list[str]
            Behaviour tags emitted by the scoring engine.

        Returns
        -------
        list[Technique]
            Deduplicated list of matching techniques, ordered by tag.
        """
        seen_ids: set[str] = set()
        results: list[Technique] = []

        for tag in behaviour_tags:
            entry = self._map.get(tag)
            if entry is None:
                continue
            tid = entry.get("technique_id", "")
            # Deduplicate by (technique_id, behaviour_tag) to allow
            # the same technique from different tags.
            dedup_key = f"{tid}:{tag}"
            if dedup_key in seen_ids:
                continue
            seen_ids.add(dedup_key)

            results.append(Technique(
                technique_id=tid,
                name=entry.get("name", ""),
                tactic=entry.get("tactic", ""),
                description=entry.get("description", "").strip(),
                behaviour_tag=tag,
            ))

        return results

    def lookup_single(self, tag: str) -> Technique | None:
        """Look up a single behaviour tag.

        Returns ``None`` if the tag is not mapped.
        """
        results = self.lookup([tag])
        return results[0] if results else None

    def all_techniques(self) -> list[Technique]:
        """Return every technique in the mapping file."""
        return self.lookup(list(self._map.keys()))

    def all_tags(self) -> list[str]:
        """Return all known behaviour tags."""
        return list(self._map.keys())
