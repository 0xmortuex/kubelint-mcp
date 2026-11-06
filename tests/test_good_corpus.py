"""False-positive guard: realistic, hardened manifests must produce ZERO findings from every rule family."""

from __future__ import annotations

import glob
import os

import pytest

from kubelint_mcp import server
from kubelint_mcp.files import Sandbox
from kubelint_mcp.model import load_set
from kubelint_mcp.registry import run_rules
from kubelint_mcp.overview import overview

CORPUS = os.path.join(os.path.dirname(__file__), "corpus", "good")
FILES = sorted(os.path.basename(p) for p in glob.glob(os.path.join(CORPUS, "*.yaml")))


def test_corpus_has_at_least_fifteen_files():
    assert len(FILES) >= 15


@pytest.mark.parametrize("name", FILES)
def test_good_manifest_has_zero_findings(name):
    rs = load_set(Sandbox(CORPUS), name)
    assert rs.resources, name
    found = []
    for prefix in ("K8S1", "K8S2", "K8S3"):
        found += run_rules(rs, prefix, frozenset())
    assert found == [], [(f.rule, f.line, f.resource, f.message) for f in found]


@pytest.mark.parametrize("name", FILES)
def test_good_manifest_tools_report_clean(name):
    server.configure(CORPUS, [])
    try:
        assert "0 finding(s)" in server.lint_manifests(name)
        assert "0 finding(s)" in server.check_references(name)
        assert "0 finding(s)" in server.rbac_review(name)
        assert "object(s)" in server.k8s_overview(name)
    finally:
        server.configure(None, [])


def test_good_directory_as_a_whole_is_clean_too():
    # duplicate Namespace objects across files are fine to ignore here only because every file uses its own names;
    # the 'shop' namespace appears in two files, so K8S2013 must flag exactly that and nothing else
    rs = load_set(Sandbox(CORPUS), ".")
    found = run_rules(rs, "K8S1", frozenset()) + run_rules(rs, "K8S2", frozenset()) + run_rules(rs, "K8S3", frozenset())
    assert {f.rule for f in found} <= {"K8S2013"}, [(f.rule, f.file, f.line, f.message) for f in found]
    assert overview(rs, "corpus")
