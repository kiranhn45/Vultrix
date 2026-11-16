# The severity model

## What it is for

Some advisories publish no severity at all (many `PYSEC`, `RUSTSEC` and `GO` records).
Without help, the scoring rules would have to treat every one of them as "medium".
The model estimates, from the advisory's own words and weakness classes (CWE ids),
how likely it is to be **high or critical**.

It is used only when no severity is published. Its output is always shown as an
estimate, with the words that drove it, and it is capped below a published "high".
Everything else in the ranking is rule-based (see [scoring.md](scoring.md)).

## How it was built

- **Data:** OSV's public exports for PyPI, npm, Go and crates.io. Malware reports and
  withdrawn advisories were dropped, and records describing the same issue were merged.
- **Labels:** advisories that do publish a severity. High or critical counts as 1.
- **Split by time:** the oldest 80% (16,751 advisories, 2005-12-31 to
  2026-06-11) trained the model. The newest 20% (4,188 advisories,
  2026-06-11 to 2026-11-14) tested it. The model is judged only on
  advisories newer than anything it saw.
- **Model:** logistic regression over 1,601 features (words, word pairs, CWE ids).
  A feature must appear in at least 30 advisories across at least 8 different packages,
  so the model cannot memorise package names.
- **No libraries:** training and prediction are plain Python. The weights are a JSON
  file (`src/valtrix/risk/severity_model.json`) that is read as data, never executed.

## How well it works

Measured on the test set (52% of which is high or critical):

| Method | Accuracy | AUC |
|---|---|---|
| Severity model | 65.7% | 0.716 |
| Keyword rules (the baseline) | 53.3% | 0.586 |
| Always say "medium" | 48.2% | 0.500 |

AUC is the chance that a randomly chosen high-severity advisory gets a higher estimate
than a randomly chosen lower-severity one (0.5 is a coin flip, 1.0 is perfect).

**Read this honestly.** The model is clearly better than the keyword rules, and it is
still wrong about one advisory in three. Severity is hard to read from a description.
That is why the estimate only fills a gap, is labelled, and cannot push a finding
above one with a published rating. A test in the suite fails if the shipped model does
not beat the baseline.

## Using and retraining it

    valtrix model                 # show these numbers for the installed model
    valtrix scan . --no-ml        # use the keyword rules instead

To retrain, download the exports and run the script (standard library only, about 20 seconds):

    for e in PyPI npm Go crates.io; do
      curl -O "https://osv-vulnerabilities.storage.googleapis.com/$e/all.zip" && mv all.zip "$e.zip"
    done
    python scripts/train_model.py PyPI.zip npm.zip Go.zip crates.io.zip

The script prints the evaluation and writes it into the model file, so the numbers
shown by `valtrix model` always belong to the weights that are installed.
