"""
tests/test_scoring_speed.py
The typosquat check was the reason pages took 20-50 s on a large database.  It now
prunes impossible comparisons, exits early and remembers results per domain.  These
tests prove the answers did not change.
"""
from __future__ import annotations

import dataclasses
import random
import string

import pytest

from core.scoring import risk_score
from core.scoring.risk_score import (
    RiskScorer,
    ScoreFactor,
    _has_homoglyphs,
    _normalize_homoglyphs,
    levenshtein,
    levenshtein_bounded,
)


@pytest.fixture(scope="module")
def scorer() -> RiskScorer:
    return RiskScorer()


def _reference_lookalike(scorer: RiskScorer, domain: str) -> ScoreFactor | None:
    """The original algorithm: every brand, exact edit distance, no pruning, no cache."""
    section = scorer._w_section("lookalike")
    threshold = int(section.get("levenshtein_threshold", 2))
    homoglyph_pts = float(section.get("homoglyph_points", 15))
    levenshtein_pts = float(section.get("levenshtein_points", 12))
    max_pts = float(section.get("max_points", 15))
    lower = domain.lower()
    if _has_homoglyphs(lower):
        normalised = _normalize_homoglyphs(lower)
        for brand in scorer._brands:
            if normalised == brand:
                return ScoreFactor("lookalike", round(min(homoglyph_pts, max_pts), 1),
                                   f"Homoglyph attack: '{domain}' looks like '{brand}' after normalisation")
    parts = lower.split(".")
    registrable = ".".join(parts[-2:]) if len(parts) >= 2 else lower
    for brand in scorer._brands:
        if registrable == brand:
            continue
        dist = levenshtein(registrable, brand)
        if dist <= threshold:
            return ScoreFactor("lookalike", round(min(levenshtein_pts, max_pts), 1),
                               f"Typosquat: '{registrable}' is {dist} edit(s) from '{brand}'")
    return None


def _mutate(rng: random.Random, text: str, edits: int) -> str:
    chars = list(text)
    for _ in range(edits):
        op = rng.choice("sdi")
        pos = rng.randrange(max(1, len(chars)))
        if op == "s" and chars:
            chars[pos % len(chars)] = rng.choice(string.ascii_lowercase + "01")
        elif op == "d" and len(chars) > 1:
            del chars[pos % len(chars)]
        else:
            chars.insert(pos, rng.choice(string.ascii_lowercase))
    return "".join(chars)


class TestBoundedEditDistance:
    @pytest.mark.parametrize("limit", [0, 1, 2, 3, 5])
    def test_matches_exact_distance_capped_at_limit_plus_one(self, limit: int) -> None:
        rng = random.Random(1234 + limit)
        for _ in range(1500):
            a = "".join(rng.choice("abc.") for _ in range(rng.randint(0, 12)))
            b = _mutate(rng, a, rng.randint(0, 4)) if rng.random() < 0.6 else \
                "".join(rng.choice("abc.") for _ in range(rng.randint(0, 12)))
            assert levenshtein_bounded(a, b, limit) == min(levenshtein(a, b), limit + 1), (a, b, limit)

    @pytest.mark.parametrize(
        ("a", "b", "limit", "expected"),
        [("", "", 2, 0), ("abc", "", 2, 3), ("abc", "", 3, 3), ("", "abcd", 2, 3),
         ("paypa1.com", "paypal.com", 2, 1), ("same", "same", 0, 0), ("abc", "xyz", 2, 3),
         ("kitten", "sitting", 3, 3), ("kitten", "sitting", 2, 3)],
    )
    def test_examples(self, a: str, b: str, limit: int, expected: int) -> None:
        assert levenshtein_bounded(a, b, limit) == expected

    def test_symmetric(self) -> None:
        assert levenshtein_bounded("microsoft.com", "micros0ft.com", 2) == \
            levenshtein_bounded("micros0ft.com", "microsoft.com", 2) == 1


class TestLookalikeUnchanged:
    def _domains(self, scorer: RiskScorer) -> list[str]:
        rng = random.Random(42)
        brands = scorer._brands
        domains = [b for b in brands]                                   # the brands themselves
        for brand in brands:
            for edits in (1, 2, 3):
                domains.append(_mutate(rng, brand, edits))              # near misses
            domains.append("mail." + brand)                             # sub-domains
            domains.append(brand.upper())
        for _ in range(2500):                                           # unrelated names
            label = "".join(rng.choice(string.ascii_lowercase + "-") for _ in range(rng.randint(3, 14)))
            domains.append(label.strip("-") + rng.choice([".com", ".net", ".org", ".top"]))
        domains += ["paypa1.com", "micros0ft-online-verify.net", "g00gle.com", "pаypal.com",   # Cyrillic а
                    "a.b", "x", "", "...", "a.b.c.d.e.f.g.com"]
        return domains

    def test_identical_to_the_original_algorithm_on_thousands_of_domains(self, scorer: RiskScorer) -> None:
        fresh = RiskScorer()                                            # empty cache: first answers are real
        checked = 0
        for domain in self._domains(fresh):
            expected = _reference_lookalike(fresh, domain)
            actual = fresh._score_lookalike(domain)
            assert actual == expected, domain
            checked += 1
        assert checked > 2500

    def test_detects_known_typosquats(self, scorer: RiskScorer) -> None:
        assert scorer._score_lookalike("paypa1.com") is not None
        assert "paypal.com" in scorer._score_lookalike("paypa1.com").reason
        assert scorer._score_lookalike("paypal.com") is None            # the real brand is not a lookalike


class TestLookalikeCache:
    def test_second_lookup_does_no_work(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fresh = RiskScorer()
        calls = {"n": 0}
        real = risk_score.levenshtein_bounded

        def counting(*args, **kwargs):
            calls["n"] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(risk_score, "levenshtein_bounded", counting)
        first = fresh._score_lookalike("some-unrelated-name.com")
        work = calls["n"]
        assert work > 0
        assert fresh._score_lookalike("SOME-unrelated-NAME.com") == first       # case-insensitive key
        assert calls["n"] == work                                              # nothing recomputed

    def test_cached_answers_cannot_be_modified_by_callers(self) -> None:
        fresh = RiskScorer()
        one = fresh._score_lookalike("paypa1.com")
        with pytest.raises(dataclasses.FrozenInstanceError):
            one.points = 999.0                                                  # immutable, so sharing is safe
        assert fresh._score_lookalike("paypa1.com") == one

    def test_negative_results_are_cached_too(self) -> None:
        fresh = RiskScorer()
        assert fresh._score_lookalike("nothing-like-a-brand-zzzz.com") is None
        assert "nothing-like-a-brand-zzzz.com" in fresh._lookalike_cache

    def test_cache_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(risk_score, "_LOOKALIKE_CACHE_MAX", 3)
        fresh = RiskScorer()
        for i in range(10):
            fresh._score_lookalike(f"domain{i}.com")
        assert len(fresh._lookalike_cache) <= 3

    def test_each_scorer_has_its_own_cache(self) -> None:
        a, b = RiskScorer(), RiskScorer()
        a._score_lookalike("example-one.com")
        assert "example-one.com" in a._lookalike_cache and "example-one.com" not in b._lookalike_cache

    def test_new_weights_apply_after_creating_a_new_scorer(self, tmp_path) -> None:
        """The dashboard re-creates the scorer when weights are saved, which resets the cache."""
        strict = tmp_path / "w.yaml"
        strict.write_text("lookalike:\n  max_points: 15\n  levenshtein_threshold: 0\n  levenshtein_points: 12\n"
                          "  homoglyph_points: 15\n", encoding="utf-8")
        # "paypall.com" has no look-alike characters, only an edit-distance match
        assert RiskScorer()._score_lookalike("paypall.com") is not None
        assert RiskScorer(weights_path=strict)._score_lookalike("paypall.com") is None
