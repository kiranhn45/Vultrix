#!/usr/bin/env python3
"""Train and evaluate the severity model shipped in src/valtrix/risk/severity_model.json.

    python scripts/train_model.py PyPI.zip npm.zip Go.zip crates.io.zip

The inputs are OSV's public per-ecosystem exports:

    https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip

What it does:

  1. Reads every advisory, drops malware reports and withdrawn records, and
     merges records that describe the same issue (the same merge the scanner uses).
  2. Keeps the advisories that publish a severity. Label: high or critical = 1.
  3. Splits by publication date: the oldest 80% train the model and the newest
     20% test it, so it is judged on advisories newer than anything it has seen.
  4. Trains a logistic regression (plain Python, no libraries) on words, word
     pairs and CWE ids. Features must appear in several different packages, so
     the model cannot simply memorise package names.
  5. Scores the model and the keyword-rule baseline on the same test set and
     writes both results into the model file.

Only the standard library is used, and the run is reproducible (fixed seed).
"""

from __future__ import annotations

import argparse
import datetime
import json
import math
import random
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from valtrix.databases.osv import OsvError, parse_vulnerability  # noqa: E402
from valtrix.models import Vulnerability, merge_related  # noqa: E402
from valtrix.risk.cvss import best_score, label_for_score  # noqa: E402
from valtrix.risk.severity_model import (  # noqa: E402
    MODEL_PATH, SeverityModel, features_of, keyword_estimate, sigmoid,
)

SEED = 20261115
# These settings were chosen on a validation slice cut from the training
# period (its newest 15%), never on the test set.
MIN_DOCUMENTS = 30      # a feature must appear in at least this many advisories
MIN_PACKAGES = 8        # ... spread over at least this many different packages
MAX_FEATURES = 2000
EPOCHS = 5
LEARNING_RATE = 0.02
L2 = 1e-3
MIN_WEIGHT = 0.02       # smaller weights are dropped from the shipped file


def severity_of(vuln: Vulnerability) -> Optional[str]:
    if vuln.severity_label:
        return vuln.severity_label
    score = best_score(vuln.cvss)
    return label_for_score(score) if score is not None else None


def load(paths: Sequence[str]) -> Tuple[List[Tuple[Vulnerability, str]], Counter]:
    """Return (advisory, package) pairs and a count of what was read."""
    stats: Counter = Counter()
    records: List[Vulnerability] = []
    package_of: Dict[str, str] = {}
    for path in paths:
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if not name.endswith(".json"):
                    continue
                stats["records read"] += 1
                if name.startswith("MAL-"):
                    stats["malware reports skipped"] += 1
                    continue
                try:
                    raw = json.loads(archive.read(name))
                    package = raw["affected"][0]["package"]
                    vuln = parse_vulnerability(raw, package["name"], package["ecosystem"])
                except (ValueError, KeyError, IndexError, TypeError, OsvError):
                    stats["unreadable skipped"] += 1
                    continue
                if vuln is None:
                    stats["withdrawn skipped"] += 1
                    continue
                records.append(vuln)
                package_of[vuln.id] = f'{package["ecosystem"]}/{package["name"]}'.lower()
    merged = merge_related(records)
    stats["distinct issues"] = len(merged)
    return [(v, package_of.get(v.id, "")) for v in merged], stats


def auc(scores: Sequence[float], labels: Sequence[int]) -> float:
    """Area under the ROC curve: chance a random positive outranks a random negative."""
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    positives = sum(labels)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return float("nan")
    total = sum(rank for rank, label in zip(ranks, labels) if label)
    return (total - positives * (positives + 1) / 2) / (positives * negatives)


def measure(scores: Sequence[float], labels: Sequence[int]) -> Dict[str, float]:
    n = len(labels)
    predicted = [1 if s >= 0.5 else 0 for s in scores]
    tp = sum(1 for p, y in zip(predicted, labels) if p and y)
    fp = sum(1 for p, y in zip(predicted, labels) if p and not y)
    fn = sum(1 for p, y in zip(predicted, labels) if not p and y)
    return {
        "auc": round(auc(scores, labels), 4),
        "accuracy": round(sum(1 for p, y in zip(predicted, labels) if p == y) / n, 4),
        "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
        "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "brier": round(sum((s - y) ** 2 for s, y in zip(scores, labels)) / n, 4),
    }


def train(rows: List[Tuple[List[int], int]], width: int, rng: random.Random) -> Tuple[float, List[float]]:
    """Logistic regression with AdaGrad and L2 regularisation."""
    weights = [0.0] * width
    squares = [1e-8] * width
    bias, bias_square = 0.0, 1e-8
    for _ in range(EPOCHS):
        rng.shuffle(rows)
        for indices, label in rows:
            error = sigmoid(bias + sum(weights[i] for i in indices)) - label
            bias_square += error * error
            bias -= LEARNING_RATE * error / math.sqrt(bias_square)
            for i in indices:
                gradient = error + L2 * weights[i]
                squares[i] += gradient * gradient
                weights[i] -= LEARNING_RATE * gradient / math.sqrt(squares[i])
    return bias, weights


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("exports", nargs="+", help="OSV all.zip files")
    parser.add_argument("--output", default=str(MODEL_PATH))
    args = parser.parse_args()
    rng = random.Random(SEED)

    advisories, stats = load(args.exports)
    labelled = []
    for vuln, package in advisories:
        severity = severity_of(vuln)
        if severity is None or not vuln.published or not (vuln.summary or vuln.details):
            stats["no published severity (what the model is for)"] += severity is None
            continue
        labelled.append((vuln.published, vuln, package, 1 if severity in ("HIGH", "CRITICAL") else 0))
    labelled.sort(key=lambda row: (row[0], row[1].id))
    cut = int(len(labelled) * 0.8)
    train_set, test_set = labelled[:cut], labelled[cut:]

    documents: Counter = Counter()
    packages: Dict[str, Set[str]] = defaultdict(set)
    train_features = []
    for _, vuln, package, label in train_set:
        present = features_of(vuln)
        train_features.append((present, label))
        documents.update(present)
        for feature in present:
            if len(packages[feature]) < MIN_PACKAGES:
                packages[feature].add(package)
    vocabulary = [
        f for f, count in documents.most_common()
        if count >= MIN_DOCUMENTS and len(packages[f]) >= MIN_PACKAGES
    ][:MAX_FEATURES]
    index = {feature: i for i, feature in enumerate(vocabulary)}

    rows = [([index[f] for f in present if f in index], label) for present, label in train_features]
    bias, weights = train(rows, len(vocabulary), rng)
    kept = {f: round(w, 4) for f, w in zip(vocabulary, weights) if abs(w) >= MIN_WEIGHT}
    model = SeverityModel(round(bias, 4), kept)

    labels = [label for *_, label in test_set]
    share = sum(labels) / len(labels)
    evaluation = {
        "model": measure([model.estimate(v).probability for _, v, _, _ in test_set], labels),
        "keyword_rules": measure([keyword_estimate(v).probability for _, v, _, _ in test_set], labels),
        "always_medium": {"accuracy": round(1 - share, 4), "auc": 0.5},
    }
    document = {
        "format": 1,
        "task": "probability that an advisory is high or critical severity",
        "trained_on": datetime.date.today().isoformat(),
        "sources": sorted(Path(p).name for p in args.exports),
        "training": {
            "advisories": len(train_set),
            "published_from": train_set[0][0][:10], "published_to": train_set[-1][0][:10],
            "features": len(kept),
        },
        "test": {
            "advisories": len(test_set),
            "published_from": test_set[0][0][:10], "published_to": test_set[-1][0][:10],
            "share_high_or_critical": round(share, 4),
        },
        "evaluation": evaluation,
        "bias": model.bias,
        "weights": dict(sorted(kept.items())),
    }
    Path(args.output).write_text(json.dumps(document, indent=0, sort_keys=False) + "\n", encoding="utf-8")

    for label, count in stats.items():
        print(f"{count:>8}  {label}")
    print(f"{len(train_set):>8}  training advisories ({document['training']['published_from']} to {document['training']['published_to']})")
    print(f"{len(test_set):>8}  test advisories ({document['test']['published_from']} to {document['test']['published_to']}), {share:.1%} high or critical")
    print(f"{len(kept):>8}  features kept\n")
    for name, numbers in evaluation.items():
        print(f"{name:>14}: " + ", ".join(f"{k} {v}" for k, v in numbers.items()))
    top = sorted(kept.items(), key=lambda item: item[1])
    print("\nPushes towards high:  " + ", ".join(f for f, _ in top[-15:][::-1]))
    print("Pushes towards lower: " + ", ".join(f for f, _ in top[:15]))
    print(f"\nWrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
