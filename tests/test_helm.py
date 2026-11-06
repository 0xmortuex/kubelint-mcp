"""render_helm: the only subprocess. Refusals are tested for real; execution is tested with a fake `helm` on PATH
(a real script run as a real process) and, when a real helm exists, with a real chart."""

from __future__ import annotations

import os
import shutil
import stat
import sys

import pytest

from conftest import write
from kubelint_mcp import helm as helm_mod
from kubelint_mcp import server
from kubelint_mcp.errors import UserError

OUT = "---\n# Source: demo/templates/svc.yaml\napiVersion: v1\nkind: Service\nmetadata:\n  name: demo\n  namespace: n\nspec:\n  type: LoadBalancer\n  ports:\n    - port: 80\n"


@pytest.fixture
def chart(tmp_path):
    server.configure(str(tmp_path), [])
    write(str(tmp_path / "chart" / "Chart.yaml"), "apiVersion: v2\nname: demo\nversion: 0.1.0\n")
    write(str(tmp_path / "chart" / "templates" / "cm.yaml"), "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}-cfg\n  namespace: {{ .Release.Namespace }}\ndata:\n  a: b\n")
    write(str(tmp_path / "vals.yaml"), "a: 1\n")
    yield tmp_path
    server.configure(None, [])


def install_fake_helm(directory, monkeypatch, stdout=OUT, code=0, stderr="", sleep=0):
    d = directory / "bin"
    d.mkdir(exist_ok=True)
    write(str(d / "out.yaml"), stdout)
    write(str(d / "err.txt"), stderr)
    if sys.platform == "win32":
        script = d / "helm.cmd"
        body = "@echo off\r\necho %* > \"%~dp0args.txt\"\r\n"
        if sleep:
            body += f"ping -n {sleep + 1} 127.0.0.1 > nul\r\n"
        body += "type \"%~dp0err.txt\" 1>&2\r\ntype \"%~dp0out.yaml\"\r\n" + f"exit /b {code}\r\n"
        with open(script, "w", newline="", encoding="utf-8") as fh:
            fh.write(body)
    else:
        script = d / "helm"
        body = "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$(dirname \"$0\")/args.txt\"\n"
        if sleep:
            body += f"sleep {sleep}\n"
        body += "cat \"$(dirname \"$0\")/err.txt\" 1>&2\ncat \"$(dirname \"$0\")/out.yaml\"\n" + f"exit {code}\n"
        with open(script, "w", newline="\n", encoding="utf-8") as fh:
            fh.write(body)
        os.chmod(script, os.stat(script).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", str(d) + os.pathsep + os.environ.get("PATH", ""))
    return d


def test_refuses_without_allow_exec_and_explains(chart):
    with pytest.raises(UserError, match="allow_exec=true"):
        server.render_helm("chart")


def test_reports_missing_helm_binary(chart, monkeypatch):
    monkeypatch.setattr(helm_mod.shutil, "which", lambda name: None)
    with pytest.raises(UserError, match="`helm` binary was not found"):
        server.render_helm("chart", allow_exec=True)


def test_rejects_non_chart_directory_and_bad_names(chart):
    (chart / "plain").mkdir()
    with pytest.raises(UserError, match="not a Helm chart"):
        server.render_helm("plain", allow_exec=True)
    for bad in ("x; rm -rf /", "UPPER", "-flag", "a" * 80, ""):
        with pytest.raises(UserError, match="release_name"):
            server.render_helm("chart", release_name=bad, allow_exec=True)
    with pytest.raises(UserError, match="namespace"):
        server.render_helm("chart", namespace="$(whoami)", allow_exec=True)


def test_values_file_must_be_inside_the_sandbox(chart):
    outside = chart.parent / "outside_vals.yaml"
    write(str(outside), "a: 1\n")
    try:
        with pytest.raises(UserError, match="outside the directory"):
            server.render_helm("chart", values_file=str(outside), allow_exec=True)
    finally:
        outside.unlink()


def test_runs_helm_with_an_argument_list_and_lints_the_output(chart, monkeypatch):
    d = install_fake_helm(chart, monkeypatch)
    out = server.render_helm("chart", values_file="vals.yaml", release_name="rel", namespace="prod", allow_exec=True)
    assert "K8S1028" in out and "helm template output:" in out
    args = (d / "args.txt").read_text(encoding="utf-8")
    for token in ("template", "rel", "--namespace", "prod", "--values"):
        assert token in args
    assert "--validate" not in args and "--dry-run" not in args and "kubectl" not in args


def test_helm_failure_is_reported_with_exit_code(chart, monkeypatch):
    install_fake_helm(chart, monkeypatch, stdout="", code=1, stderr="Error: template: demo/templates/x.yaml:3: bad")
    with pytest.raises(UserError, match=r"failed \(exit code 1\).*bad"):
        server.render_helm("chart", allow_exec=True)


def test_helm_timeout(chart, monkeypatch):
    install_fake_helm(chart, monkeypatch, sleep=6)
    monkeypatch.setattr(helm_mod, "TIMEOUT_SECONDS", 1)
    with pytest.raises(UserError, match="did not finish within 1 seconds"):
        server.render_helm("chart", allow_exec=True)


def test_oversized_helm_output_is_refused(chart, monkeypatch):
    install_fake_helm(chart, monkeypatch, stdout="x: " + "y" * 3000 + "\n")
    monkeypatch.setattr(helm_mod, "MAX_OUTPUT_BYTES", 1000)
    with pytest.raises(UserError, match="more than 1000 bytes"):
        server.render_helm("chart", allow_exec=True)


def test_kubeconfig_is_not_passed_to_helm(chart, monkeypatch):
    seen = {}
    real_run = helm_mod.subprocess.run

    def spy(cmd, **kw):
        seen["env"] = kw.get("env")
        seen["cmd"] = cmd
        return real_run(cmd, **kw)

    install_fake_helm(chart, monkeypatch)
    monkeypatch.setenv("KUBECONFIG", "/should/not/leak")
    monkeypatch.setattr(helm_mod.subprocess, "run", spy)
    server.render_helm("chart", allow_exec=True)
    assert "KUBECONFIG" not in seen["env"] and isinstance(seen["cmd"], list)


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed here; real-helm rendering is not exercised")
def test_real_helm_renders_a_real_chart(chart):
    out = server.render_helm("chart", release_name="rel", namespace="prod", allow_exec=True)
    assert "1 object(s)" in out
