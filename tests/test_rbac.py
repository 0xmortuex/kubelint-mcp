"""RBAC review (K8S3xxx): each case marks the expected line."""

from __future__ import annotations

import pytest

from conftest import marked_lines

ROLE = "apiVersion: rbac.authorization.k8s.io/v1\nkind: %s\nmetadata:\n  name: r\n%srules:\n%s"
BIND = "apiVersion: rbac.authorization.k8s.io/v1\nkind: %s\nmetadata:\n  name: b\n%sroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: %s\n  name: %s\nsubjects:\n%s"
NS = "  namespace: shop\n"


def role(kind: str, rules: str) -> str:
    return ROLE % (kind, NS if kind == "Role" else "", rules)


def bind(kind: str, role_kind: str, role_name: str, subjects: str) -> str:
    return BIND % (kind, NS if kind == "RoleBinding" else "", role_kind, role_name, subjects)


SA = "  - kind: ServiceAccount\n    name: web\n    namespace: shop\n"

CASES = {
    "3001-wildcard-verbs": ("K8S3001", role("ClusterRole", "  - apiGroups: [\"\"]\n    resources: [pods]\n    verbs: [\"*\"] # !K8S3001\n")),
    "3001-wildcard-verbs-in-role": ("K8S3001", role("Role", "  - apiGroups: [\"\"]\n    resources: [pods]\n    verbs: [\"*\"] # !K8S3001\n")),
    "3002-wildcard-resources": ("K8S3002", role("ClusterRole", "  - apiGroups: [\"\"]\n    resources: [\"*\"] # !K8S3002\n    verbs: [get]\n")),
    "3003-crb-cluster-admin": ("K8S3003", bind("ClusterRoleBinding", "ClusterRole", "cluster-admin", SA).replace("roleRef:", "roleRef: # !K8S3003")),
    "3004-rb-cluster-admin": ("K8S3004", bind("RoleBinding", "ClusterRole", "cluster-admin", SA).replace("roleRef:", "roleRef: # !K8S3004")),
    "3005-reads-secrets": ("K8S3005", role("ClusterRole", "  - apiGroups: [\"\"] # !K8S3005\n    resources: [secrets]\n    verbs: [get, list]\n").replace("  - apiGroups: [\"\"] # !K8S3005", "  - apiGroups: [\"\"] # !K8S3005")),
    "3005-watch-secrets-with-names": ("K8S3005", role("Role", "  - apiGroups: [\"\"] # !K8S3005\n    resources: [secrets]\n    resourceNames: [app]\n    verbs: [list, watch]\n")),
    "3006-escalate": ("K8S3006", role("ClusterRole", "  - apiGroups: [rbac.authorization.k8s.io]\n    resources: [clusterroles]\n    verbs: [escalate, get] # !K8S3006\n")),
    "3006-bind": ("K8S3006", role("ClusterRole", "  - apiGroups: [rbac.authorization.k8s.io]\n    resources: [clusterroles]\n    verbs: [bind] # !K8S3006\n")),
    "3006-impersonate": ("K8S3006", role("ClusterRole", "  - apiGroups: [\"\"]\n    resources: [users]\n    verbs: [impersonate] # !K8S3006\n")),
    "3007-default-sa": ("K8S3007", bind("RoleBinding", "Role", "r", "  - kind: ServiceAccount # !K8S3007\n    name: default\n    namespace: shop\n")),
    "3008-anonymous": ("K8S3008", bind("ClusterRoleBinding", "ClusterRole", "view", "  - kind: User # !K8S3008\n    name: system:anonymous\n    apiGroup: rbac.authorization.k8s.io\n")),
    "3008-unauthenticated": ("K8S3008", bind("ClusterRoleBinding", "ClusterRole", "view", "  - kind: Group # !K8S3008\n    name: system:unauthenticated\n    apiGroup: rbac.authorization.k8s.io\n")),
    "3009-authenticated": ("K8S3009", bind("ClusterRoleBinding", "ClusterRole", "view", "  - kind: Group # !K8S3009\n    name: system:authenticated\n    apiGroup: rbac.authorization.k8s.io\n")),
    "3010-pods-exec": ("K8S3010", role("Role", "  - apiGroups: [\"\"] # !K8S3010\n    resources: [pods/exec]\n    verbs: [create]\n")),
    "3011-nodes-proxy": ("K8S3011", role("ClusterRole", "  - apiGroups: [\"\"] # !K8S3011\n    resources: [nodes/proxy]\n    verbs: [get]\n")),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_rbac_problem_reported_at_marked_line(lint_text, name):
    rule, text = CASES[name]
    marks = marked_lines(text, rule)
    assert marks, name
    found = lint_text(text, "K8S3")
    hits = [f for f in found if f.rule == rule]
    assert hits, f"{rule} missing; got {[(f.rule, f.line) for f in found]}"
    assert any(f.line in marks for f in hits), (rule, [f.line for f in hits], marks)


@pytest.mark.parametrize(
    "text",
    [
        role("Role", "  - apiGroups: [\"\"]\n    resources: [pods, configmaps]\n    verbs: [get, list, watch]\n"),
        role("Role", "  - apiGroups: [\"\"]\n    resources: [secrets]\n    resourceNames: [app-config]\n    verbs: [get]\n"),
        role("ClusterRole", "  - nonResourceURLs: [/healthz]\n    verbs: [get]\n"),
        bind("RoleBinding", "ClusterRole", "view", SA),
        bind("ClusterRoleBinding", "ClusterRole", "system:auth-delegator", SA),
        bind("RoleBinding", "ClusterRole", "edit", "  - kind: Group\n    name: developers\n    apiGroup: rbac.authorization.k8s.io\n"),
    ],
)
def test_least_privilege_rbac_has_no_findings(lint_text, text):
    assert lint_text(text, "K8S3") == []


def test_rbac_review_lists_bindings_over_stdio_text(load):
    from kubelint_mcp.rules_rbac import summary

    rs = load({"rbac.yaml": role("Role", "  - apiGroups: [\"\"]\n    resources: [pods]\n    verbs: [get]\n") + "---\n" + bind("RoleBinding", "Role", "r", SA)})
    lines = summary(rs)
    assert any(ln.startswith("Role r") for ln in lines) and any("RoleBinding b" in ln and "ServiceAccount shop/web" in ln for ln in lines)


def test_rbac_case_count():
    assert len(CASES) >= 12
