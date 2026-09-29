"""Ground-truth corpus model for the benchmark harness.

A corpus describes, for a known vulnerable target, exactly which vulnerabilities
*should* be found (the ground truth) keyed by a stable identity. The scoring
engine compares the platform's findings against this to compute precision/recall.

Identity matching is deliberately coarse and deterministic: a finding matches a
ground-truth entry when their (method, normalized_path, owasp_category) triple
agrees. This mirrors how a triager would say "yes, that's the BOLA on
/users/{id}" without depending on volatile evidence like timestamps or bodies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# OWASP API Security Top 10 (2023) — the category vocabulary the corpus and
# findings are scored against. LLM_API covers the OWASP LLM Top 10 surface.
OWASP_API_CATEGORIES = {
    "API1_BOLA",
    "API2_BROKEN_AUTH",
    "API3_BOPLA",
    "API4_RESOURCE_CONSUMPTION",
    "API5_BFLA",
    "API6_SENSITIVE_BUSINESS_FLOW",
    "API7_SSRF",
    "API8_MISCONFIGURATION",
    "API9_IMPROPER_INVENTORY",
    "API10_UNSAFE_CONSUMPTION",
    "LLM_API",
}

# Severity vocabulary, ordered. High/Critical are the SLO-gated tiers.
SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
HIGH_CRITICAL = {"HIGH", "CRITICAL"}


def normalize_path(path: str) -> str:
    """Collapse concrete identifiers to ``{id}`` so /users/42 and /users/99 match.

    Numeric, UUID, and long-hex segments become ``{id}``; existing ``{param}``
    templating is preserved as ``{id}`` too so corpus and live findings align.
    """
    if not path:
        return "/"
    text = path.strip()
    # Drop query string and fragment.
    text = text.split("?", 1)[0].split("#", 1)[0]
    if not text.startswith("/"):
        text = "/" + text
    segments = []
    for segment in text.split("/"):
        if not segment:
            segments.append("")
            continue
        if segment.startswith("{") and segment.endswith("}"):
            segments.append("{id}")
        elif _looks_like_identifier(segment):
            segments.append("{id}")
        else:
            segments.append(segment.lower())
    normalized = "/".join(segments)
    if len(normalized) > 1:
        normalized = normalized.rstrip("/")
    return normalized or "/"


_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _looks_like_identifier(segment: str) -> bool:
    if segment.isdigit():
        return True
    if _UUID_RE.match(segment):
        return True
    if len(segment) >= 16 and re.fullmatch(r"[0-9a-fA-F]+", segment):
        return True
    return False


@dataclass(frozen=True)
class GroundTruth:
    """One known vulnerability that the platform is expected to find."""

    method: str
    path: str
    owasp_category: str
    severity: str = "HIGH"
    title: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        if self.owasp_category not in OWASP_API_CATEGORIES:
            raise ValueError(
                f"unknown owasp_category {self.owasp_category!r}; "
                f"must be one of {sorted(OWASP_API_CATEGORIES)}"
            )
        if self.severity.upper() not in SEVERITY_RANK:
            raise ValueError(f"unknown severity {self.severity!r}")

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.method.upper(), normalize_path(self.path), self.owasp_category)


@dataclass
class Corpus:
    """A target's full ground-truth set plus metadata."""

    target_name: str
    base_url: str
    description: str = ""
    ground_truth: list[GroundTruth] = field(default_factory=list)

    @property
    def identities(self) -> set[tuple[str, str, str]]:
        return {gt.identity for gt in self.ground_truth}

    def categories(self) -> set[str]:
        return {gt.owasp_category for gt in self.ground_truth}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Corpus":
        return cls(
            target_name=str(data["target_name"]),
            base_url=str(data.get("base_url", "")),
            description=str(data.get("description", "")),
            ground_truth=[
                GroundTruth(
                    method=str(entry["method"]),
                    path=str(entry["path"]),
                    owasp_category=str(entry["owasp_category"]),
                    severity=str(entry.get("severity", "HIGH")).upper(),
                    title=str(entry.get("title", "")),
                    notes=str(entry.get("notes", "")),
                )
                for entry in data.get("ground_truth", [])
            ],
        )

    @classmethod
    def load(cls, path: str | Path) -> "Corpus":
        raw = Path(path).read_text(encoding="utf-8")
        return cls.from_dict(yaml.safe_load(raw))
