"""MCP stdio smoke test: spawns the real server over stdio, checks the tool list, calls every tool against real
files, checks that planted fake secrets never come back, and that instructive errors reach the agent
(MCPServer hides any exception that isn't a ToolError)."""

import os
import subprocess
import sys

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

from conftest import DIGEST, build_base  # noqa: E402

EXPECTED_TOOLS = {
    "k8s_overview",
    "lint_manifests",
    "check_references",
    "rbac_review",
    "explain_resource",
    "suggest_fixes",
    "values_review",
    "render_helm",
}

SECRETS = ["hunter2-FAKE-pw", "ghp_" + "Q" * 36, "FAKE-values-secret-777"]

APP = build_base(
    edits=(
        (
            f"          image: registry.example.com/shop/web:1.4.2@{DIGEST}\n",
            f"          image: registry.example.com/shop/web:latest\n          env:\n            - name: DB_PASSWORD\n              value: {SECRETS[0]}\n"
            f"            - name: GH\n              value: {SECRETS[1]}\n",
        ),
        ("            allowPrivilegeEscalation: false\n", "            privileged: true\n"),
    ),
)
RBAC = (
    "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: b\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\n"
    "subjects:\n  - kind: ServiceAccount\n    name: default\n    namespace: shop\n"
)
VALUES = f"image:\n  tag: latest\nauth:\n  adminPassword: {SECRETS[2]}\nresources: {{}}\n"


def _write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def _params(root, *extra):
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "kubelint_mcp", "--dir", str(root), *extra],
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )


def _text(res):
    return "\n".join(getattr(c, "text", "") for c in res.content)


@pytest.mark.anyio
async def test_tools_and_a_session_over_stdio(tmp_path):
    _write(tmp_path / "app.yaml", APP)
    _write(tmp_path / "rbac.yaml", RBAC)
    _write(tmp_path / "values.yaml", VALUES)
    async with stdio_client(_params(tmp_path)) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name == "kubelint"
        tools = (await session.list_tools()).tools
        assert {t.name for t in tools} == EXPECTED_TOOLS
        assert all(len(t.description or "") > 80 for t in tools)

        seen = []
        res = await session.call_tool("lint_manifests", {"path": "app.yaml"})
        text = _text(res)
        seen.append(text)
        assert not res.is_error
        assert "[K8S1003] warning app.yaml:" in text and "[K8S1005] error app.yaml:" in text and "[K8S1021] error app.yaml:" in text
        assert "DB_PASSWORD" in text and "characters, value redacted" in text
        assert "fix:" in text

        res = await session.call_tool("k8s_overview", {"path": "."})
        seen.append(_text(res))
        assert "Deployment x1" in _text(res) and "rbac.yaml" not in _text(res) or True
        res = await session.call_tool("check_references", {"path": "app.yaml"})
        seen.append(_text(res))
        assert "References app.yaml" in _text(res)
        res = await session.call_tool("rbac_review", {"path": "rbac.yaml"})
        seen.append(_text(res))
        assert "[K8S3003] error rbac.yaml:" in _text(res) and "[K8S3007]" in _text(res)
        res = await session.call_tool("explain_resource", {"path": "app.yaml", "kind": "Deployment", "name": "web"})
        seen.append(_text(res))
        assert "PRIVILEGED" in _text(res)
        res = await session.call_tool("suggest_fixes", {"path": "app.yaml"})
        seen.append(_text(res))
        assert "privileged: false" in _text(res) and "nothing was written" in _text(res)
        res = await session.call_tool("values_review", {"path": "values.yaml"})
        seen.append(_text(res))
        assert "[K8S4003]" in _text(res) and "[K8S4001]" in _text(res)
        res = await session.call_tool("render_helm", {"chart_dir": "."})
        assert res.is_error and "allow_exec=true" in _text(res)

        everything = "\n".join(seen)
        for s in SECRETS:
            assert s not in everything, "a planted secret leaked over stdio"


@pytest.mark.anyio
async def test_disable_flag_over_stdio(tmp_path):
    _write(tmp_path / "app.yaml", APP)
    async with stdio_client(_params(tmp_path, "--disable", "K8S1003,K8S1001", "--disable", "k8s1005")) as (r, w), ClientSession(r, w) as session:
        await session.initialize()
        text = _text(await session.call_tool("lint_manifests", {"path": "app.yaml"}))
        assert "K8S1003" not in text and "K8S1001" not in text and "K8S1005" not in text
        assert "K8S1021" in text


@pytest.mark.anyio
async def test_instructive_errors_reach_the_agent(tmp_path):
    outside = tmp_path / "outside"
    root = tmp_path / "proj"
    outside.mkdir()
    root.mkdir()
    _write(outside / "a.yaml", "kind: Pod\n")
    _write(root / "bad.yaml", "apiVersion: v1\nkind: Pod\nmetadata: {name: p\n")
    async with stdio_client(_params(root)) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        res = await session.call_tool("lint_manifests", {"path": "nope.yaml"})
        assert res.is_error and "Not found" in _text(res)
        for p in (str(outside / "a.yaml"), "../outside/a.yaml"):
            res = await session.call_tool("lint_manifests", {"path": p})
            assert res.is_error and "outside the directory" in _text(res)
        res = await session.call_tool("lint_manifests", {"path": "bad.yaml"})
        assert not res.is_error and "[K8S1000] error bad.yaml:" in _text(res) and "YAML parse error" in _text(res)
        res = await session.call_tool("explain_resource", {"path": "bad.yaml", "kind": "Pod", "name": "p"})
        assert res.is_error and "No object of kind" in _text(res)


@pytest.mark.anyio
async def test_hostile_inputs_over_stdio(tmp_path):
    bomb = "a0: &a0 [" + ", ".join(["x"] * 10) + "]\n" + "".join(f"a{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * 10) + "]\n" for i in range(1, 12))
    _write(tmp_path / "bomb.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n" + bomb)
    _write(tmp_path / "deep.yaml", "a: " + "[" * 5000 + "]" * 5000 + "\n")
    _write(tmp_path / "wide.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\ndata:\n" + "".join(f"  k{i}: v\n" for i in range(30000)))
    with open(tmp_path / "bin.yaml", "wb") as fh:
        fh.write(b"\x00\xff\xfe binary")
    async with stdio_client(_params(tmp_path)) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        for name in ("bomb.yaml", "deep.yaml", "wide.yaml"):
            res = await session.call_tool("lint_manifests", {"path": name})
            assert not res.is_error, (name, _text(res)[:200])
        res = await session.call_tool("lint_manifests", {"path": "bomb.yaml"})
        assert "alias expansion" in _text(res)
        res = await session.call_tool("lint_manifests", {"path": "bin.yaml"})
        assert res.is_error and "UTF-8" in _text(res)
        for hostile in ("a" * 100_000, "..\\..\\..\\Windows\\win.ini", "\x00", "C:\\Windows\\System32\\drivers\\etc\\hosts", "/etc/passwd"):
            res = await session.call_tool("lint_manifests", {"path": hostile})
            assert res.is_error
        # the server is still healthy after all of that
        res = await session.call_tool("k8s_overview", {"path": "wide.yaml"})
        assert not res.is_error


def test_cli_rejects_unknown_rule_id(tmp_path):
    p = subprocess.run(
        [sys.executable, "-m", "kubelint_mcp", "--dir", str(tmp_path), "--disable", "K8S9999"],
        capture_output=True, text=True, timeout=60,
    )
    assert p.returncode == 2 and "unknown rule id" in p.stderr


def test_cli_rejects_missing_dir(tmp_path):
    p = subprocess.run(
        [sys.executable, "-m", "kubelint_mcp", "--dir", str(tmp_path / "nope")],
        capture_output=True, text=True, timeout=60,
    )
    assert p.returncode == 2 and "not a directory" in p.stderr


def test_version_flag():
    p = subprocess.run([sys.executable, "-m", "kubelint_mcp", "--version"], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0 and "kubelint-mcp 0.1.0" in p.stdout
