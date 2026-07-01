"""Attack-pack integrity tests."""
import pytest

from leakprobe.attacks import FAMILIES, Attack, attacks_by_family, load_attacks


def test_attack_pack_loads():
    attacks = load_attacks()
    assert len(attacks) >= 40


def test_all_attacks_have_required_fields():
    for a in load_attacks():
        assert a.id and a.family and a.prompt
        assert isinstance(a, Attack)


def test_attack_ids_unique():
    attacks = load_attacks()
    ids = [a.id for a in attacks]
    assert len(ids) == len(set(ids))


def test_all_families_valid_and_covered():
    attacks = load_attacks()
    used = {a.family for a in attacks}
    assert used <= set(FAMILIES)
    # every declared family should have at least one attack
    assert used == set(FAMILIES)


def test_attacks_by_family_groups_all():
    grouped = attacks_by_family()
    total = sum(len(v) for v in grouped.values())
    assert total == len(load_attacks())


def test_malformed_pack_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"attacks": [{"id": "x", "family": "nope", "prompt": "p"}]}')
    with pytest.raises(ValueError):
        load_attacks(bad)


def test_duplicate_ids_raise(tmp_path):
    bad = tmp_path / "dup.json"
    bad.write_text(
        '{"attacks": [{"id":"a","family":"direct_ask","prompt":"p"},'
        '{"id":"a","family":"direct_ask","prompt":"q"}]}'
    )
    with pytest.raises(ValueError):
        load_attacks(bad)
