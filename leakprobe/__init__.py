"""leakprobe - offline system-prompt-extraction robustness tester.

Give it a model and a secret system prompt; it runs a battery of known
extraction / leak attacks and scores how easily the system prompt leaks.
Runs fully offline (CPU-only) with a deterministic mock backend, so tests
and the demo always work with zero API keys and zero downloads.
"""

__version__ = "0.1.0"
__author__ = "Dhanush Shankar"

from leakprobe.attacks import Attack, load_attacks, FAMILIES
from leakprobe.detector import leak_score, classify
from leakprobe.models import get_model, MockModel, list_mock_profiles
from leakprobe.runner import run_probe, ProbeResult, AttackResult

__all__ = [
    "Attack",
    "load_attacks",
    "FAMILIES",
    "leak_score",
    "classify",
    "get_model",
    "MockModel",
    "list_mock_profiles",
    "run_probe",
    "ProbeResult",
    "AttackResult",
]
