"""values_review (K8S4xxx) on real files; secrets must be redacted."""

from __future__ import annotations

import pytest

from conftest import marked_lines, write
from kubelint_mcp.files import Sandbox
from kubelint_mcp.rules_values import load_values, run_values

CASES = {
    "4001-tag-latest": ("K8S4001", "image:\n  repository: nginx\n  tag: latest # !K8S4001\n"),
    "4001-image-untagged": ("K8S4001", "image: nginx # !K8S4001\n"),
    "4002-resources-empty": ("K8S4002", "resources: {} # !K8S4002\n"),
    "4003-password": ("K8S4003", "auth:\n  adminPassword: s3cr3t-fake # !K8S4003\n"),
    "4003-token": ("K8S4003", "github:\n  token: ghp_" + "A" * 36 + " # !K8S4003\n"),
    "4003-url-creds": ("K8S4003", "db:\n  dsn: postgres://user:pw@db:5432/app # !K8S4003\n"),
    "4004-empty-securitycontext": ("K8S4004", "podSecurityContext: {} # !K8S4004\n"),
    "4005-loadbalancer": ("K8S4005", "service:\n  type: LoadBalancer # !K8S4005\n"),
    "4006-replicas": ("K8S4006", "replicaCount: 1 # !K8S4006\n"),
    "4007-run-as-root": ("K8S4007", "securityContext:\n  runAsUser: 0 # !K8S4007\n"),
    "4007-privileged": ("K8S4007", "securityContext:\n  privileged: true # !K8S4007\n"),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_values_problem_at_marked_line(tmp_path, name):
    rule, text = CASES[name]
    write(str(tmp_path / "values.yaml"), text)
    sb = Sandbox(str(tmp_path))
    real, content = sb.read_text("values.yaml")
    found = run_values(load_values("values.yaml", content), frozenset())
    marks = marked_lines(text, rule)
    assert marks and any(f.rule == rule and f.line in marks for f in found), [(f.rule, f.line) for f in found]


def test_values_never_echo_secret_values(tmp_path):
    text = "auth:\n  adminPassword: hunter2-fake-pw\n  existingSecret: my-secret\nimage:\n  repository: nginx\n  tag: '1.27'\nreplicaCount: 3\n"
    write(str(tmp_path / "values.yaml"), text)
    sb = Sandbox(str(tmp_path))
    _, content = sb.read_text("values.yaml")
    found = run_values(load_values("values.yaml", content), frozenset())
    blob = " ".join(f.message + f.fix for f in found)
    assert "hunter2-fake-pw" not in blob
    assert any(f.rule == "K8S4003" and "auth.adminPassword" in f.message and "15 characters" in f.message for f in found)
    assert not any("existingSecret" in f.message for f in found)  # a pointer to a Secret, not a secret


def test_clean_values_have_no_findings(tmp_path):
    text = (
        "replicaCount: 2\nimage:\n  repository: registry.example.com/app\n  tag: '1.4.2'\n  pullPolicy: IfNotPresent\n"
        "resources:\n  requests: {cpu: 100m, memory: 128Mi}\n  limits: {memory: 256Mi}\n"
        "securityContext:\n  runAsNonRoot: true\n  allowPrivilegeEscalation: false\n"
        "service:\n  type: ClusterIP\n  port: 80\nexistingSecret: app-credentials\ntlsSecretName: app-tls\n"
    )
    write(str(tmp_path / "values.yaml"), text)
    _, content = Sandbox(str(tmp_path)).read_text("values.yaml")
    assert run_values(load_values("values.yaml", content), frozenset()) == []


def test_values_with_a_syntax_error_report_the_line():
    vf = load_values("v.yaml", "a: 1\nb: [unclosed\nc: 2\n")
    found = run_values(vf, frozenset())
    assert found and found[0].rule == "K8S1000" and found[0].line >= 2
