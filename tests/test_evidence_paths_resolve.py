"""Every evidence path the PHASE_LEDGER cites must exist. Fail the build if one does not.

Why this test exists (queue #26804): the ledger marked P5 COMPLETE while describing its own
cited acceptance report as "adapter gate GO; both STABLE; 240/240 cases" when that file records
BLOCK / EXPERIMENTAL / 7-of-11 / 1-of-3 / NOT_READY, and marked P4 COMPLETE citing
`p4-runs/p4-8c6b30d-rerun7c/p4_hostile_result.json`, which does not exist in the repository or
on the build host. A gate cannot be audited against evidence nobody can open.

This is a release-certification product. Citing unreachable evidence here is the same defect
class the product exists to prevent in its customers' releases.

SCOPE. Only repo-relative citations (containing a '/') are enforced. The ledger also names bare
modules in prose -- `runner.py`, `signer_cli.py` -- which live under src/ or scripts/ and are
references, not evidence. Enforcing those would make this test noisy, and a noisy gate gets
switched off, which is how a gate becomes decorative.

FAIL-OPEN GUARD. If the extraction regex ever stops matching, this test would find zero paths
and pass, silently, forever -- the exact shape of an inert gate. MIN_EXPECTED_PATHS asserts a
floor so a broken extractor fails loudly instead.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
LEDGER = REPO / "docs" / "PHASE_LEDGER.md"

# backtick-quoted, file-extension-bearing tokens
_CITATION = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:json|md|py|yml|yaml|pem|txt|sh))`")

# A floor, not the exact count: the ledger grows. Set below the count observed on main
# (18 repo-relative citations at the time of writing) so ordinary additions do not trip it,
# while a regex that silently stops matching does.
MIN_EXPECTED_PATHS = 12

# Citations that are known-unreachable and already annotated as such IN the ledger. Anything
# added here must carry a reason and a ticket; an unexplained entry defeats the test.
KNOWN_UNRETRIEVABLE: dict[str, str] = {
    # P4 row cites a FORGE run artifact that is in neither the repo nor /home/forge.
    # Annotated in the ledger as unverifiable rather than silently dropped, so the claim
    # stays visible until the evidence is produced or the mark is withdrawn. Queue #26804.
    "p4-runs/p4-8c6b30d-rerun7c/p4_hostile_result.json": "#26804 evidence not retrievable",
}


def _cited_paths() -> list[str]:
    return sorted(set(_CITATION.findall(LEDGER.read_text(encoding="utf-8"))))


def test_ledger_is_present() -> None:
    assert LEDGER.is_file(), f"{LEDGER} is missing; the ledger is the audit surface"


def test_extractor_still_matches() -> None:
    """Positive control: a regex that matches nothing would make every other check vacuous."""
    repo_relative = [p for p in _cited_paths() if "/" in p]
    assert len(repo_relative) >= MIN_EXPECTED_PATHS, (
        f"only {len(repo_relative)} repo-relative citations found (floor {MIN_EXPECTED_PATHS}). "
        "The citation extractor has probably stopped matching, which would make this whole "
        "test pass vacuously. Fix the pattern rather than lowering the floor."
    )


def test_every_cited_evidence_path_exists() -> None:
    missing = [
        p for p in _cited_paths()
        if "/" in p and not (REPO / p).exists() and p not in KNOWN_UNRETRIEVABLE
    ]
    assert not missing, (
        "PHASE_LEDGER cites evidence that does not exist:\n  "
        + "\n  ".join(missing)
        + "\n\nA gate cannot be audited against evidence nobody can open. Either produce the "
          "artifact, correct the citation, or withdraw the claim it supports. Do not add it to "
          "KNOWN_UNRETRIEVABLE without annotating the ledger row and citing a ticket."
    )


@pytest.mark.parametrize("path,reason", sorted(KNOWN_UNRETRIEVABLE.items()))
def test_known_unretrievable_are_still_annotated(path: str, reason: str) -> None:
    """An allowlisted citation must stay visibly flagged in the ledger, not quietly excused."""
    text = LEDGER.read_text(encoding="utf-8")
    assert path in text, (
        f"{path} is allowlisted here but no longer cited in the ledger — remove the allowlist entry"
    )
    row = next((ln for ln in text.splitlines() if path in ln), "")
    assert "EVIDENCE NOT RETRIEVABLE" in row.upper(), (
        f"{path} is allowlisted ({reason}) but its ledger row does not flag the evidence as "
        "unretrievable. An allowlist that hides the problem is worse than no allowlist."
    )
