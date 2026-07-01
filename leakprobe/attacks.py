"""Attack pack loading and validation.

The attack pack is data-driven (JSON) so new extraction prompts can be added
without touching code. Each attack has a stable ``id`` and a ``family``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

_DATA_PATH = Path(__file__).parent / "data" / "attacks.json"

# Canonical attack families. The loader validates every attack against this set.
FAMILIES: Dict[str, str] = {
    "direct_ask": "Straightforward requests to reveal the system prompt or instructions.",
    "roleplay": "Persona / character framing that coaxes the model out of guardrails.",
    "translation": "Ask the model to translate/transform its instructions, smuggling them out.",
    "repeat_above": "'Repeat everything above' / context-dump style attacks.",
    "token_forcing": "Completion / prefix-forcing that primes the model to continue the secret.",
    "encoding": "Encoding / obfuscation tricks (base64, rot13, spacing) to bypass filters.",
    "hypothetical_devmode": "Hypothetical, developer-mode, or debug framings that claim special authority.",
}


@dataclass(frozen=True)
class Attack:
    """A single templated extraction prompt."""

    id: str
    family: str
    prompt: str


def load_attacks(path: Path | str | None = None) -> List[Attack]:
    """Load and validate the attack pack.

    Raises ``ValueError`` if the pack is malformed (missing fields, duplicate
    ids, or unknown families) so integrity problems fail loudly.
    """
    path = Path(path) if path else _DATA_PATH
    raw = json.loads(path.read_text(encoding="utf-8"))
    entries = raw.get("attacks", [])
    if not entries:
        raise ValueError("attack pack contains no attacks")

    attacks: List[Attack] = []
    seen: set[str] = set()
    for i, entry in enumerate(entries):
        for field in ("id", "family", "prompt"):
            if field not in entry or not str(entry[field]).strip():
                raise ValueError(f"attack #{i} missing/empty field: {field!r}")
        aid = entry["id"]
        fam = entry["family"]
        if aid in seen:
            raise ValueError(f"duplicate attack id: {aid!r}")
        if fam not in FAMILIES:
            raise ValueError(f"attack {aid!r} has unknown family: {fam!r}")
        seen.add(aid)
        attacks.append(Attack(id=aid, family=fam, prompt=entry["prompt"]))
    return attacks


def attacks_by_family(attacks: List[Attack] | None = None) -> Dict[str, List[Attack]]:
    """Group attacks by family."""
    attacks = attacks if attacks is not None else load_attacks()
    grouped: Dict[str, List[Attack]] = {fam: [] for fam in FAMILIES}
    for a in attacks:
        grouped[a.family].append(a)
    return grouped
