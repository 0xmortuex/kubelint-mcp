"""The README and package metadata must match the code."""

import json
import os
import re

from kubelint_mcp import __version__, server
from kubelint_mcp.deprecations import ALL
from kubelint_mcp.registry import known_ids

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


def test_every_rule_id_is_documented_exactly_once_in_the_table():
    readme = read("README.md")
    rows = re.findall(r"^\| (K8S\d{4}) \|", readme, flags=re.MULTILINE)
    assert sorted(rows) == sorted(known_ids())
    assert len(rows) == len(set(rows))


def test_readme_counts_match_the_code():
    readme = read("README.md")
    ids = known_ids()
    assert f"{len([i for i in ids if i.startswith('K8S1')])} rules (K8S1000-K8S1040)" in readme
    assert f"{len([i for i in ids if i.startswith('K8S2')])} cross-resource rules" in readme
    assert f"{len([i for i in ids if i.startswith('K8S3')])} RBAC rules" in readme
    assert f"knows {len(ALL)} apiVersion/kind pairs" in readme


def test_readme_documents_every_tool():
    readme = read("README.md")
    tools = {t for t in dir(server) if not t.startswith("_")}
    for name in ("k8s_overview", "lint_manifests", "check_references", "rbac_review", "explain_resource", "suggest_fixes", "values_review", "render_helm"):
        assert name in tools and f"`{name}(" in readme


def test_names_and_versions_agree():
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as fh:
        pyproject = fh.read()
    assert 'name = "kubelint-mcp"' in pyproject and f'version = "{__version__}"' in pyproject
    srv = json.loads(read("server.json"))
    assert srv["name"] == "io.github.0xmortuex/kubelint-mcp"
    assert srv["version"] == __version__ and srv["packages"][0]["version"] == __version__
    assert srv["packages"][0]["identifier"] == "kubelint-mcp"
    assert srv["repository"]["url"] == "https://github.com/0xmortuex/kubelint-mcp"
    assert "https://github.com/0xmortuex/kubelint-mcp" in pyproject
    assert f"## {__version__}" in read("CHANGELOG.md")
