# Local data folders

Only the small configuration files in this folder are tracked by git
(`scoring_weights.yaml`, `mitre_map.yaml`, `whitelist.yaml`, `brands.txt` and this file).
Everything else is a **local dataset** that is ignored by git and is not needed to run
the tool.

| Path | What it is | Used by |
|---|---|---|
| `1/` | **Ham** (10,776 ordinary mails) from the "Email Dataset" (see below). | Volume tests and the spam-vs-ham experiment. |
| `2/` | **Spam** (8,752 mails) from the same dataset. | Same. |
| `email-dataset-main.zip` | The original download of that dataset (31.5 MB); `1/` and `2/` are its contents. Keep it as the pristine source. | Re-creating `1/` and `2/`. |
| `email-dataset-README.md`, `email-dataset-LICENSE.txt` | The dataset's own README and licence (MIT-style, Jonathan Milligan, 2023). Keep them when citing the data. | Citation. |
| `Prev_Data/` | SpamAssassin public-corpus archives (`*.tar.bz2`). | `evaluation/dataset.py` reads ham samples from `20021010_easy_ham.tar.bz2`. |

## About the "Email Dataset"

19,528 mails (10,776 ham in `1/`, 8,752 spam in `2/`), cleaned to ASCII text, a mixture of
plain text and HTML. Only part of the files still carry full headers (roughly 40 to 60 %
have `From:` / `Received:` lines), so header-based checks (Received chain, SPF/DKIM/DMARC,
Reply-To) can only be measured on that subset. The spam in it is generic spam, not targeted
phishing. Mention both limits when you report results.

## Rules

* Never add real company mail to this folder inside the repository's tracked area.
* Re-creating `1/` and `2/` from the zip: extract the archive and copy its `dataset/1` and
  `dataset/2` folders here.
