"""YAML alias bombs ("billion laughs") and other expansion attacks must be refused quickly, per document."""

from __future__ import annotations

import time

from kubelint_mcp.rules_values import load_values, run_values
from kubelint_mcp.yamlpos import MAX_EXPANDED_NODES, load_documents

POD = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: n}\nspec:\n  containers:\n    - name: c\n      image: nginx:latest\n"


def bomb(levels: int = 10, width: int = 10) -> str:
    lines = ["a0: &a0 [" + ", ".join(["lol"] * width) + "]"]
    for i in range(1, levels):
        lines.append(f"a{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * width) + "]")
    return "\n".join(lines) + "\n"


def test_billion_laughs_is_refused_fast_and_reported(lint_text):
    text = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: n}\ndata:\n  x: y\n" + bomb()
    t0 = time.perf_counter()
    found = lint_text(text)
    assert time.perf_counter() - t0 < 5
    bad = [f for f in found if f.rule == "K8S1000"]
    assert len(bad) == 1 and "alias expansion" in bad[0].message and "billion-laughs" in bad[0].message


def test_bomb_in_one_document_does_not_block_the_others(lint_text):
    text = POD + "---\n" + "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: n}\n" + bomb() + "---\n" + POD.replace("name: p,", "name: q,")
    found = lint_text(text)
    assert [f.rule for f in found if f.rule == "K8S1000"] == ["K8S1000"]
    assert len([f for f in found if f.rule == "K8S1003"]) == 2


def test_bomb_through_mappings_and_merge_keys(lint_text):
    lines = ["m0: &m0 {" + ", ".join(f"k{i}: v" for i in range(10)) + "}"]
    for i in range(1, 12):
        lines.append(f"m{i}: &m{i} {{" + ", ".join(f"j{i}_{k}: *m{i - 1}" for k in range(10)) + "}")
    text = "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\n" + "\n".join(lines) + "\n"
    t0 = time.perf_counter()
    found = lint_text(text)
    assert time.perf_counter() - t0 < 5
    assert any(f.rule == "K8S1000" and "alias expansion" in f.message for f in found)
    merge = "base: &b {" + ", ".join(f"k{i}: [1,2,3]" for i in range(50)) + "}\nitems:\n" + "".join("  - <<: [*b, *b, *b, *b]\n" for _ in range(100))
    lr = load_documents(merge)
    assert lr.docs or lr.problems  # finishes, one way or the other


def test_self_referencing_alias_is_rejected(lint_text):
    found = lint_text("apiVersion: v1\nkind: Pod\nmetadata: &m {name: p, self: *m}\n")
    assert any(f.rule == "K8S1000" and "recursive" in f.message for f in found)


def test_ordinary_alias_use_is_not_penalised(lint_text):
    text = (
        "common: &resources\n  requests: {cpu: 100m, memory: 64Mi}\n  limits: {memory: 128Mi}\n"
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: n}\nspec:\n  containers:\n"
        + "".join(f"    - name: c{i}\n      image: nginx:1.27\n      resources: *resources\n" for i in range(20))
    )
    found = lint_text(text)
    assert not [f for f in found if f.rule in ("K8S1000", "K8S1001", "K8S1002")]


def test_expansion_limit_is_documented_and_high_enough_for_real_manifests():
    assert 100_000 <= MAX_EXPANDED_NODES <= 1_000_000


def test_bomb_in_values_file_is_reported():
    vf = load_values("values.yaml", bomb())
    found = run_values(vf, frozenset())
    assert found and found[0].rule == "K8S1000" and "alias expansion" in found[0].message


def test_very_wide_flat_documents_are_fine(lint_text):
    text = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: n}\ndata:\n" + "".join(f"  key{i}: v{i}\n" for i in range(20_000))
    assert not [f for f in lint_text(text) if f.rule == "K8S1000"]


def test_python_object_tags_are_never_constructed(lint_text, tmp_path):
    marker = tmp_path / "pwned.txt"
    head = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\ndata:\n"
    # scalar form: refused by the safe constructor
    found = lint_text(head + "  x: !!python/name:os.system ''\n")
    assert any(f.rule == "K8S1000" and "unsupported value" in f.message for f in found)
    # collection form: tags on sequences/mappings are never turned into objects at all
    lint_text(head + f"  x: !!python/object/apply:builtins.open [{str(marker)!r}, w]\n  y: !!python/object/apply:os.system ['echo hi']\n")
    assert not marker.exists()


def test_complex_and_odd_keys_do_not_crash(lint_text):
    for text in ("? [a, b]\n: c\n", "? {a: b}\n: c\n", "<<: [1, 2]\nx: 1\n", "1: one\ntrue: yes\nnull: x\n", "a: !!binary aGVsbG8=\n", "d: 2024-01-01\n"):
        lint_text(text)
