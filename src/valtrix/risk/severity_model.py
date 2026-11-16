"""Estimate severity for advisories that do not publish one.

Some advisories (many PYSEC, RUSTSEC and GO records) carry no severity. The
rules would otherwise have to treat them all as "medium". This module makes
an estimate from the advisory's own text and weakness classes instead:

    keyword_estimate()  a hand-written rule baseline
    SeverityModel       a logistic regression trained on advisories that do
                        publish a severity (see scripts/train_model.py)

The model is only used when nothing is published, and its output is always
labelled as an estimate. It runs in plain Python: the trained weights are a
JSON file shipped with the package, loaded as data and never executed.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from valtrix.models import Vulnerability

MODEL_PATH = Path(__file__).with_name("severity_model.json")
MAX_TEXT = 2000
_MAX_MODEL_BYTES = 5_000_000

_WORD = re.compile(r"[a-z][a-z0-9]+(?:[-'][a-z0-9]+)*")
_STOP = frozenset("""
a an and are as at be been by can could do does for from has have how if in into is it its may
of on or that the their them then there these this those to was were when where which while
will with would via using used use also not no but than such any all other more most some
""".split())


@dataclass(frozen=True)
class Estimate:
    """probability  Chance (0..1) that the advisory is high or critical severity.
    signals      The features that pushed the estimate up the most.
    source       "model" or "keywords".
    """

    probability: float
    signals: Tuple[str, ...] = ()
    source: str = "model"

    @property
    def label(self) -> str:
        if self.probability >= 0.5:
            return "HIGH"
        return "MEDIUM"


# ---------------------------------------------------------------- features

def tokenize(text: str) -> List[str]:
    return [w for w in _WORD.findall(text.lower()[:MAX_TEXT]) if w not in _STOP]


def extract_features(summary: str, details: str, cwes: Iterable[str] = ()) -> Set[str]:
    """The feature names present in one advisory: words, word pairs, weakness classes."""
    words = tokenize(f"{summary}. {details}")
    features = set(words)
    features.update(f"{a} {b}" for a, b in zip(words, words[1:]))
    features.update(c.upper() for c in cwes)
    return features


def features_of(vuln: Vulnerability) -> Set[str]:
    return extract_features(vuln.summary, vuln.details, vuln.cwes)


# ------------------------------------------------------------- rule baseline

_HIGH_HINTS = (
    "remote code execution", "arbitrary code", "code execution", "command injection",
    "sql injection", "authentication bypass", "privilege escalation", "deserialization",
    "arbitrary file", "path traversal", "directory traversal", "buffer overflow",
    "memory corruption", "use after free", "use-after-free", "rce", "takeover",
    "prototype pollution", "server-side request forgery", "ssrf", "xxe", "out-of-bounds write",
    "heap overflow", "sandbox escape", "arbitrary command", "account takeover",
)
_LOWER_HINTS = (
    "cross-site scripting", "xss", "open redirect", "information disclosure",
    "information exposure", "denial of service", "redos", "regular expression",
    "timing", "log injection", "csrf", "cross-site request forgery", "clickjacking",
    "resource exhaustion", "null pointer", "panic", "crash", "leak",
)


def keyword_estimate(vuln: Vulnerability) -> Estimate:
    """The rule baseline: look for phrases that usually mean high or lower severity."""
    text = f"{vuln.summary} {vuln.details}".lower()[:MAX_TEXT]
    high = [hint for hint in _HIGH_HINTS if hint in text]
    lower = [hint for hint in _LOWER_HINTS if hint in text]
    if high and not lower:
        probability = 0.8
    elif high:
        probability = 0.6
    elif lower:
        probability = 0.3
    else:
        probability = 0.5
    return Estimate(probability, tuple(high[:3]), "keywords")


# ----------------------------------------------------------------- the model

def sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-value))
    e = math.exp(value)
    return e / (1.0 + e)


class SeverityModel:
    def __init__(self, bias: float, weights: Dict[str, float], info: Optional[Dict[str, Any]] = None) -> None:
        self.bias = bias
        self.weights = weights
        self.info = info or {}

    @classmethod
    def from_dict(cls, data: Any) -> "SeverityModel":
        """Build from decoded JSON. Raises ValueError if the shape is wrong."""
        if not isinstance(data, dict) or data.get("format") != 1:
            raise ValueError("not a Valtrix severity model")
        bias, weights = data.get("bias"), data.get("weights")
        if not isinstance(bias, (int, float)) or isinstance(bias, bool) or not isinstance(weights, dict):
            raise ValueError("severity model is missing its weights")
        clean: Dict[str, float] = {}
        for name, weight in weights.items():
            if (not isinstance(name, str) or isinstance(weight, bool)
                    or not isinstance(weight, (int, float)) or not math.isfinite(weight)):
                raise ValueError("severity model has an invalid weight")
            clean[name] = float(weight)
        info = {k: v for k, v in data.items() if k not in ("bias", "weights")}
        return cls(float(bias), clean, info)

    @classmethod
    def load(cls, path: Optional[Path] = None) -> Optional["SeverityModel"]:
        """Load the shipped model. Returns None if it is missing or damaged."""
        path = path or MODEL_PATH
        try:
            if path.stat().st_size > _MAX_MODEL_BYTES:
                return None
            return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError, RecursionError):
            return None

    def score(self, features: Iterable[str]) -> float:
        return self.bias + sum(self.weights.get(f, 0.0) for f in features)

    def estimate(self, vuln: Vulnerability) -> Estimate:
        present = features_of(vuln)
        pulls = sorted(
            ((self.weights[f], f) for f in present if f in self.weights), reverse=True
        )
        signals = tuple(name for weight, name in pulls[:3] if weight > 0)
        return Estimate(sigmoid(self.score(present)), signals, "model")


_cached: Optional[Tuple[Optional[SeverityModel]]] = None


def default_model() -> Optional[SeverityModel]:
    """The shipped model, loaded once."""
    global _cached
    if _cached is None:
        _cached = (SeverityModel.load(),)
    return _cached[0]


def estimate_severity(vuln: Vulnerability, model: Optional[SeverityModel] = None,
                      use_model: bool = True) -> Estimate:
    """Model estimate when a model is available, otherwise the keyword baseline."""
    if use_model:
        model = model or default_model()
        if model is not None:
            return model.estimate(vuln)
    return keyword_estimate(vuln)
