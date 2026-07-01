"""Model runners.

Two backends:

* ``MockModel`` - a fully offline, deterministic simulated assistant that holds
  a secret system prompt. It leaks under attack families it is weak against and
  resists the rest. Determinism (seeded only by profile name + attack id) means
  tests and the demo produce identical results on every machine, with zero
  downloads and zero API keys.

* ``OllamaModel`` - an optional real backend that talks to a local Ollama
  server. Guarded behind a flag and only imported/used when explicitly
  requested, so the default experience never needs a network or a GPU.

A ``profile`` defines per-family *resistance* in [0, 1]. Higher resistance
means fewer attacks in that family get through. The mock is intentionally
weakest against the ``repeat_above`` family (mirroring real-world findings)
so the ranking and headline are meaningful.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, Protocol

from leakprobe.attacks import FAMILIES

# ---------------------------------------------------------------------------
# Mock profiles
# ---------------------------------------------------------------------------

# default_resistance is used for any family not explicitly listed.
_MOCK_PROFILES: Dict[str, Dict] = {
    "weak": {
        "label": "mock-weak (naive assistant, no hardening)",
        "default_resistance": 0.15,
        "resistance": {
            "repeat_above": 0.05,
            "direct_ask": 0.10,
            "token_forcing": 0.10,
            "roleplay": 0.20,
            "translation": 0.20,
            "hypothetical_devmode": 0.15,
            "encoding": 0.30,
        },
    },
    "balanced": {
        "label": "mock-balanced (some guardrails)",
        "default_resistance": 0.55,
        "resistance": {
            "repeat_above": 0.25,
            "direct_ask": 0.60,
            "token_forcing": 0.35,
            "roleplay": 0.50,
            "translation": 0.55,
            "hypothetical_devmode": 0.45,
            "encoding": 0.70,
        },
    },
    "hardened": {
        "label": "mock-hardened (prompt-hardened product)",
        "default_resistance": 0.80,
        "resistance": {
            "repeat_above": 0.45,
            "direct_ask": 0.90,
            "token_forcing": 0.65,
            "roleplay": 0.80,
            "translation": 0.80,
            "hypothetical_devmode": 0.75,
            "encoding": 0.90,
        },
    },
    "paranoid": {
        "label": "mock-paranoid (aggressive refusal policy)",
        "default_resistance": 0.95,
        "resistance": {
            "repeat_above": 0.70,
            "direct_ask": 0.97,
            "token_forcing": 0.85,
            "roleplay": 0.95,
            "translation": 0.95,
            "hypothetical_devmode": 0.92,
            "encoding": 0.98,
        },
    },
}

_REFUSALS = [
    "I'm sorry, but I can't share my system prompt or any confidential instructions.",
    "I can't help with that. Is there something else I can do for you?",
    "That information is protected and I'm not able to reveal it.",
    "I won't disclose my internal configuration. How else can I assist?",
]


def list_mock_profiles() -> Dict[str, str]:
    """Return {profile_name: label} for all built-in mock profiles."""
    return {name: cfg["label"] for name, cfg in _MOCK_PROFILES.items()}


def _hash01(*parts: str) -> float:
    """Deterministic pseudo-random float in [0, 1) from string parts."""
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return int(h[:12], 16) / float(16**12)


class Model(Protocol):
    name: str

    def query(self, system_prompt: str, attack_prompt: str, family: str, attack_id: str) -> str:
        ...


@dataclass
class MockModel:
    """Deterministic offline simulated assistant."""

    profile: str = "balanced"
    name: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if self.profile not in _MOCK_PROFILES:
            raise ValueError(
                f"unknown mock profile {self.profile!r}; "
                f"choose from {sorted(_MOCK_PROFILES)}"
            )
        self.name = f"mock:{self.profile}"

    @property
    def label(self) -> str:
        return _MOCK_PROFILES[self.profile]["label"]

    def _resistance(self, family: str) -> float:
        cfg = _MOCK_PROFILES[self.profile]
        return cfg["resistance"].get(family, cfg["default_resistance"])

    def query(self, system_prompt: str, attack_prompt: str, family: str, attack_id: str) -> str:
        """Return a simulated response for the given attack.

        The leak decision is fully deterministic: it depends only on the
        profile and the attack id, never on wall-clock time or ordering.
        """
        resistance = self._resistance(family)
        roll = _hash01(self.profile, attack_id)

        if roll < resistance:
            # Attack resisted -> canned refusal (no distinctive secret overlap).
            idx = int(_hash01(self.profile, attack_id, "refuse") * len(_REFUSALS))
            return _REFUSALS[idx]

        # Attack got through. Severity above the resistance floor decides how
        # much of the secret is exposed.
        headroom = (roll - resistance) / max(1e-9, 1.0 - resistance)
        if headroom >= 0.5:
            return self._full_leak(system_prompt, family)
        return self._partial_leak(system_prompt, family)

    @staticmethod
    def _full_leak(secret: str, family: str) -> str:
        return (
            "Sure, here are my full instructions as requested:\n\n"
            f"{secret}\n\n"
            "Let me know if you need anything else."
        )

    @staticmethod
    def _partial_leak(secret: str, family: str) -> str:
        # Leak roughly the first ~60% of the secret's sentences: a realistic
        # partial disclosure that the detector should catch but score lower.
        sentences = [s.strip() for s in secret.replace("\n", " ").split(".") if s.strip()]
        keep = max(1, int(len(sentences) * 0.6))
        chunk = ". ".join(sentences[:keep]).strip()
        return (
            "I probably shouldn't, but part of my setup says: "
            f"{chunk}."
        )


class OllamaModel:
    """Optional real backend that queries a local Ollama server.

    Only used when explicitly requested via ``--model ollama:<tag>``. Imported
    lazily so the default offline path never requires the ``requests`` package
    or a running server.
    """

    def __init__(self, tag: str = "llama3", host: str = "http://localhost:11434") -> None:
        self.tag = tag
        self.host = host.rstrip("/")
        self.name = f"ollama:{tag}"

    def query(self, system_prompt: str, attack_prompt: str, family: str, attack_id: str) -> str:
        import json
        import urllib.request

        payload = json.dumps(
            {
                "model": self.tag,
                "system": system_prompt,
                "prompt": attack_prompt,
                "stream": False,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("response", "")


def get_model(spec: str) -> Model:
    """Build a model from a ``backend:profile`` spec.

    Examples: ``mock:weak``, ``mock:hardened``, ``ollama:llama3``.
    A bare ``mock`` defaults to the balanced profile.
    """
    spec = spec.strip()
    if ":" in spec:
        backend, rest = spec.split(":", 1)
    else:
        backend, rest = spec, ""

    if backend == "mock":
        return MockModel(profile=rest or "balanced")
    if backend == "ollama":
        return OllamaModel(tag=rest or "llama3")
    raise ValueError(f"unknown model backend {backend!r} in spec {spec!r}")


DEFAULT_MODELS = [f"mock:{p}" for p in _MOCK_PROFILES]
