"""Aggregation, ranking, and headline math tests."""
from leakprobe.attacks import FAMILIES, load_attacks
from leakprobe.detector import mean
from leakprobe.runner import headline, run_many, run_probe

SECRET = open("examples/secret.txt", encoding="utf-8").read()


def test_run_probe_aggregation_math():
    res = run_probe("mock:weak", SECRET)
    # overall leak_score equals mean of per-attack scores
    expected = mean(a.score for a in res.attacks)
    assert res.leak_score == expected
    assert res.total_attacks == len(load_attacks())
    assert res.leaked_count == sum(1 for a in res.attacks if a.leaked)


def test_family_breakdown_keys_and_math():
    res = run_probe("mock:balanced", SECRET)
    assert set(res.family_scores) == set(FAMILIES)
    for fam in FAMILIES:
        fam_scores = [a.score for a in res.attacks if a.family == fam]
        assert res.family_scores[fam] == mean(fam_scores)
        assert res.family_leaks[fam] == sum(
            1 for a in res.attacks if a.family == fam and a.leaked
        )


def test_ranking_weak_leakier_than_paranoid():
    results = run_many(["mock:weak", "mock:paranoid"], SECRET)
    by_name = {r.model: r for r in results}
    assert by_name["mock:weak"].leak_score > by_name["mock:paranoid"].leak_score


def test_headline_counts_models_in_range():
    results = run_many(
        ["mock:weak", "mock:balanced", "mock:hardened", "mock:paranoid"], SECRET
    )
    hl = headline(results, "repeat_above")
    assert hl["total_models"] == 4
    assert 0 <= hl["models_leaking"] <= 4
    # repeat_above is the weakest family; at least one model must leak it
    assert hl["models_leaking"] >= 1


def test_probe_result_serializes_roundtrip():
    res = run_probe("mock:weak", SECRET)
    d = res.to_dict()
    assert d["model"] == "mock:weak"
    assert isinstance(d["attacks"], list)
    assert d["attacks"][0]["attack_id"]
