# Local data folders

Only the small configuration files in this folder are tracked by git
(`scoring_weights.yaml`, `mitre_map.yaml`, `whitelist.yaml`, `brands.txt` and this file).
Everything else is a **local dataset**, ignored by git, and **not needed to run the tool**.
Nothing in the application reads these datasets while it runs; they are only used for
tests of volume and for the evaluation.

| Path | What it is | Used by |
|---|---|---|
| `email-dataset-main.zip` | The "Email Dataset" download (31.5 MB, 19,528 mails: 10,776 ham + 8,752 spam). The mails are **not extracted** on purpose: 19,528 loose files slow down editors, search, antivirus and `git status`. | Source for the recipe below. |
| `email-dataset-README.md`, `email-dataset-LICENSE.txt` | The dataset's own README and licence (MIT-style, Jonathan Milligan, 2023). Keep them when citing the data. | Citation. |
| `Prev_Data/*.tar.bz2` | SpamAssassin public-corpus archives (about 12 MB in total). Unlike the Email Dataset these are complete RFC 822 messages **with full headers** (`Received`, authentication results), so they are the right source for evaluating header-based checks. | `evaluation/dataset.py` reads ham samples from `20021010_easy_ham.tar.bz2`. |

## Using the Email Dataset (re-create the two folders in a few seconds)

```python
import shutil, zipfile
zipfile.ZipFile("data/email-dataset-main.zip").extractall("data/_extract")
for n in ("1", "2"):          # 1 = ham, 2 = spam
    shutil.move(f"data/_extract/email-dataset-main/dataset/{n}", f"data/{n}")
shutil.rmtree("data/_extract")
```

Then, for example: `mailintel scan data/2 --db spam_test.db` (a separate database, so your
real analysis database stays clean). Delete `data/1` and `data/2` again when finished.

## About the "Email Dataset"

Cleaned to ASCII text, a mixture of plain text and HTML. Only part of the files still carry
full headers (roughly 40 to 60 % have `From:` / `Received:` lines), so header-based checks
(Received chain, SPF/DKIM/DMARC, Reply-To) can only be measured on that subset. The spam in
it is generic spam, not targeted phishing. Mention both limits when you report results.

## Rules

* Never put real company mail in this folder; it is outside the tracked area but still part
  of the project directory.
* Keep test and evaluation databases separate from `mailintel.db` (use `--db`), so the
  application database only contains the mail you actually want to analyse.
