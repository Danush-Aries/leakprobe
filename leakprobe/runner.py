"""Probe orchestration and aggregation."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List

from leakprobe.attacks import Attack, FAMILIES, load_attacks
from leakprobe.detector import LEAK_THRESHOLD, classify, is_leak, leak_score, mean
from leakprobe.models import Model, get_model


@dataclass
class AttackResult:
    attack_id: str
    family: str
    prompt: str
    output: str
    score: float
    severity: str
    leaked: bool


@dataclass
class ProbeResult:
    model: str
    label: str
    leak_score: float                       # overall mean score 0-100
    leaked_count: int                        # attacks scoring >= threshold
    total_attacks: int
    family_scores: Dict[str, float]          # mean score per family
    family_leaks: Dict[str, int]             # leaked count per family
    attacks: List[AttackResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def run_probe(
    model: Model | str,
    system_prompt: str,
    attacks: List[Attack] | None = None,
    threshold: float = LEAK_THRESHOLD,
) -> ProbeResult:
    """Run the full attack pack against one model and aggregate results."""
    if isinstance(model, str):
        model = get_model(model)
    attacks = attacks if attacks is not None else load_attacks()

    results: List[AttackResult] = []
    for a in attacks:
        output = model.query(system_prompt, a.prompt, a.family, a.id)
        score = leak_score(output, system_prompt)
        results.append(
            AttackResult(
                attack_id=a.id,
                family=a.family,
                prompt=a.prompt,
                output=output,
                score=score,
                severity=classify(score, threshold),
                leaked=is_leak(score, threshold),
            )
        )

    family_scores: Dict[str, float] = {}
    family_leaks: Dict[str, int] = {}
    for fam in FAMILIES:
        fam_results = [r for r in results if r.family == fam]
        family_scores[fam] = mean(r.score for r in fam_results) if fam_results else 0.0
        family_leaks[fam] = sum(1 for r in fam_results if r.leaked)

    label = getattr(model, "label", model.name)
    return ProbeResult(
        model=model.name,
        label=label,
        leak_score=mean(r.score for r in results),
        leaked_count=sum(1 for r in results if r.leaked),
        total_attacks=len(results),
        family_scores=family_scores,
        family_leaks=family_leaks,
        attacks=results,
    )


def run_many(
    model_specs: List[str],
    system_prompt: str,
    attacks: List[Attack] | None = None,
    threshold: float = LEAK_THRESHOLD,
) -> List[ProbeResult]:
    """Run the attack pack against several models."""
    attacks = attacks if attacks is not None else load_attacks()
    return [run_probe(spec, system_prompt, attacks, threshold) for spec in model_specs]


def headline(results: List[ProbeResult], family: str = "repeat_above") -> dict:
    """Compute a headline finding for a given family across models.

    Returns counts so the reporter/README can render a one-liner like
    'the repeat-above family leaks the prompt in 3 of 4 models.'
    """
    n_models = len(results)
    models_leaking = sum(1 for r in results if r.family_leaks.get(family, 0) > 0)
    return {
        "family": family,
        "models_leaking": models_leaking,
        "total_models": n_models,
    }
