# MailIntel — Explainable Risk Scoring Model

## Overview

MailIntel computes a **0–100 risk score** at two levels:

1. **Per-IOC** — each IP, domain, URL, or hash is scored individually.
2. **Per-Email** — the email as a whole is scored by combining header analysis, content analysis, and the worst IOC score.

Every point is **explained**: the scorer returns a list of `(factor, points, reason)` triples so the UI can display _why_ a score is what it is.

---

## Architecture

```
data/scoring_weights.yaml   ← tunable weights (no code changes needed)
data/brands.txt              ← brand list for typosquat detection
data/mitre_map.yaml          ← behaviour → ATT&CK technique mapping
                ↓
core/scoring/risk_score.py   ← RiskScorer engine
core/mapping/mitre_attack.py ← MitreMapper (behaviour tags → T-codes)
                ↓
    IocScore / EmailScore    ← result dataclasses with breakdown
```

---

## Scoring Factors

### Per-IOC Factors

| Factor | Max Points | Source | Logic |
|--------|-----------|--------|-------|
| **VirusTotal** | 30 | Enrichment | `(malicious + suspicious×0.5) / total × 30`. Minimum 5 pts if ≥ 1 engine flags malicious. |
| **AbuseIPDB** | 20 | Enrichment | `(confidence_score / 100) × 20`. Direct linear mapping from AbuseIPDB's 0–100 confidence. |
| **Domain Age** | 15 | RDAP enrichment | < 7 days → 15 pts (newly registered). < 30 days → 10.5 pts. < 90 days → 6 pts. ≥ 90 days → 0. |
| **Lookalike** | 15 | Brand list + algorithms | Homoglyph substitution detected → 15 pts. Levenshtein distance ≤ 2 → 12 pts. |
| **Frequency** | 10 | Database | `min(frequency / 20 × 10, 10)`. IOCs seen across many emails score higher. |

### Per-Email Factors

| Factor | Max Points | Source | Logic |
|--------|-----------|--------|-------|
| **Auth Failure** | 15 | Parser `AuthResults` | SPF fail/softfail: 6. DKIM fail: 5. DMARC fail: 8. Sum clamped to 15. |
| **Reply-To Mismatch** | 10 | Parser `HeaderInfo` | Full 10 pts when `From` domain ≠ `Reply-To` domain. |
| **Dangerous Attachment** | 15 | Parser `AttachmentInfo` | Executable extensions: 15 pts. Macro-enabled docs: 12 pts. Double extensions: 15 pts. |
| **IOC Intelligence** | 35 | Per-IOC scores | `max(ioc_score) × 0.5`, capped at 35. The worst IOC lifts the email score. |

### Final Score

```
IOC Score  = clamp(sum_of_factors, 0, 100)
Email Score = clamp(sum_of_factors, 0, 100)
```

---

## Weight Configuration

All weights live in [`data/scoring_weights.yaml`](../data/scoring_weights.yaml). Example:

```yaml
virustotal:
  max_points: 30
  min_hit_points: 5

abuseipdb:
  max_points: 20

domain_age:
  max_points: 15
  newly_registered_days: 7
  recently_registered_days: 30
  young_domain_days: 90
```

To retune the model, edit the YAML and restart — no code changes required.

---

## Typosquat & Homoglyph Detection

### Levenshtein Distance

The scorer compares every extracted domain against [`data/brands.txt`](../data/brands.txt) using edit distance. If `levenshtein(domain, brand) ≤ threshold` (default: 2), the domain is flagged.

Examples:
- `paypa1.com` → `paypal.com` (distance 1) → **flagged**
- `microsfot.com` → `microsoft.com` (distance 2) → **flagged**
- `totallyunknown.com` → (distance > 2 from all brands) → **not flagged**

### Homoglyph Check

Characters from the Cyrillic, Greek, and other scripts that visually resemble Latin letters are normalised and compared:

| Original | Homoglyph | Script |
|----------|-----------|--------|
| a | а (U+0430) | Cyrillic |
| e | е (U+0435) | Cyrillic |
| o | о (U+043E) | Cyrillic |
| p | р (U+0440) | Cyrillic |
| c | с (U+0441) | Cyrillic |

Example: `pаypal.com` (Cyrillic 'а') normalises to `paypal.com` → **flagged as homoglyph attack**.

---

## Behaviour Tags & MITRE ATT&CK Mapping

The scoring engine emits **behaviour tags** for every risk signal detected. These tags are mapped to MITRE ATT&CK technique IDs via [`data/mitre_map.yaml`](../data/mitre_map.yaml).

### Example Flow

```
Email has .exe attachment
    → scorer emits tag: "phishing_attachment"
    → MitreMapper returns: T1566.001 (Phishing: Spear-phishing Attachment)

Email has SPF=fail
    → scorer emits tag: "spf_failure"
    → MitreMapper returns: T1586.002 (Compromise Accounts: Email Accounts)
```

### Covered ATT&CK Techniques

| Tag | Technique | Tactic |
|-----|-----------|--------|
| `phishing_attachment` | T1566.001 | Initial Access |
| `phishing_link` | T1566.002 | Initial Access |
| `user_execution_attachment` | T1204.002 | Execution |
| `user_execution_link` | T1204.001 | Execution |
| `macro_execution` | T1059.005 | Execution |
| `script_execution` | T1059.007 | Execution |
| `powershell_execution` | T1059.001 | Execution |
| `masquerading` | T1036 | Defence Evasion |
| `masquerading_double_extension` | T1036.007 | Defence Evasion |
| `disk_image_delivery` | T1553.005 | Defence Evasion |
| `newly_registered_domain` | T1583.001 | Resource Development |
| `malware_delivery` | T1105 | Command and Control |
| `spf_failure` / `dkim_failure` / `dmarc_failure` | T1586.002 | Resource Development |

---

## Score Breakdown in the UI

The scorer returns structured breakdown objects that the UI can render directly:

```python
from core.scoring import RiskScorer

scorer = RiskScorer()
result = scorer.score_email(
    auth_results={"spf": "fail", "dkim": "pass", "dmarc": "fail"},
    from_addr="support@bank.com",
    reply_to="attacker@evil.com",
    attachments=[{"filename": "invoice.exe"}],
)

print(f"Score: {result.score}/100")
for factor in result.breakdown:
    print(f"  +{factor.points:5.1f}  {factor.factor}: {factor.reason}")
```

Output:
```
Score: 39.0/100
  + 14.0  auth_failure: Auth failures: SPF fail, DMARC fail
  + 10.0  reply_to_mismatch: Reply-To domain (evil.com) ≠ From domain (bank.com)
  + 15.0  dangerous_attachment: Dangerous attachment: invoice.exe
```

---

## Testing

Tests are in:
- [`tests/test_scoring.py`](../tests/test_scoring.py) — 30+ test cases covering every factor
- [`tests/test_mitre.py`](../tests/test_mitre.py) — 15+ test cases for MITRE mapping

Run all tests:
```bash
pytest tests/test_scoring.py tests/test_mitre.py -v
```

---

## Design Rationale

1. **Explainability over accuracy**: Every point is attributable to a named factor with a human-readable reason. This is critical for forensic reports and analyst trust.

2. **Configurable without code**: Weights in YAML mean the model can be retuned by analysts or during evaluation without touching Python.

3. **Defence-in-depth scoring**: No single factor can reach 100 alone. A truly dangerous email needs _multiple_ signals to converge (e.g., VT hit + auth failure + dangerous attachment).

4. **Graceful degradation**: Missing enrichment data → that factor simply contributes 0 points. The scorer never crashes.

5. **MITRE integration**: Behaviour tags bridge the scoring engine to ATT&CK, enabling technique-level reporting in STIX exports and incident reports.
