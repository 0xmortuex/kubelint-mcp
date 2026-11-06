"""K8S3xxx: RBAC review. Roles, ClusterRoles and their bindings."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from .findings import Hit
from .model import Resource, ResourceSet, as_dict, as_list
from .registry import rule

Hits = Iterator[Hit]
READ_VERBS = {"get", "list", "watch", "*"}


def _rules(res: Resource) -> Iterator[tuple[int, dict[str, Any], set[str], set[str], set[str]]]:
    if res.kind not in ("Role", "ClusterRole"):
        return
    for i, r in enumerate(as_list(res.get("rules"))):
        r = as_dict(r)
        verbs = {str(v) for v in as_list(r.get("verbs"))}
        resources = {str(v) for v in as_list(r.get("resources"))}
        names = {str(v) for v in as_list(r.get("resourceNames"))}
        yield i, r, verbs, resources, names


def _scope(res: Resource) -> str:
    return "cluster-wide" if res.kind == "ClusterRole" else f"in namespace {res.ns or '(current)'}"


@rule("K8S3001", "error", "wildcard verbs in a role")
def wildcard_verbs(res: Resource, rs: ResourceSet) -> Hits:
    for i, r, verbs, resources, _ in _rules(res):
        if "*" in verbs:
            full = "*" in resources
            yield res.hit(("rules", i, "verbs"), f"{res.label} grants every verb ('*') {_scope(res)}" + (" on every resource: this is cluster-admin in disguise" if full and res.kind == "ClusterRole" else ""),
                          "List only the verbs the subject needs (for example get, list, watch).")


@rule("K8S3002", "error", "wildcard resources in a role")
def wildcard_resources(res: Resource, rs: ResourceSet) -> Hits:
    for i, r, verbs, resources, _ in _rules(res):
        if "*" in resources:
            yield res.hit(("rules", i, "resources"), f"{res.label} applies to every resource type ('*') {_scope(res)}, including Secrets and RBAC objects",
                          "Name the resources explicitly (for example pods, configmaps), and restrict apiGroups.")


@rule("K8S3003", "error", "ClusterRoleBinding to cluster-admin")
def crb_cluster_admin(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind == "ClusterRoleBinding" and as_dict(res.get("roleRef")).get("name") == "cluster-admin":
        yield res.hit(("roleRef",), f"{res.label} gives cluster-admin (full control of the whole cluster) to: {_subjects(res)}",
                      "Bind a narrower ClusterRole (view, edit) or a custom Role in the namespaces needed.")


@rule("K8S3004", "warning", "RoleBinding to cluster-admin")
def rb_cluster_admin(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind == "RoleBinding" and as_dict(res.get("roleRef")).get("name") == "cluster-admin":
        yield res.hit(("roleRef",), f"{res.label} gives cluster-admin rights inside namespace {res.ns or '(current)'} to: {_subjects(res)}",
                      "Bind the built-in 'admin' or 'edit' ClusterRole, or a custom Role, instead of cluster-admin.")


@rule("K8S3005", "warning", "role can read Secrets")
def reads_secrets(res: Resource, rs: ResourceSet) -> Hits:
    for i, r, verbs, resources, names in _rules(res):
        if "secrets" not in resources or not (verbs & READ_VERBS):
            continue
        if names and not (verbs & {"list", "watch", "*"}):
            continue
        yield res.hit(("rules", i), f"{res.label} can {'/'.join(sorted(verbs & READ_VERBS))} Secrets {_scope(res)}" + ("" if names else " (all of them)"),
                      "Restrict with resourceNames, grant access to a narrower namespace via Role, or drop Secrets access and use projected volumes.")


@rule("K8S3006", "error", "escalate, bind or impersonate verb")
def escalation_verbs(res: Resource, rs: ResourceSet) -> Hits:
    for i, r, verbs, resources, _ in _rules(res):
        bad = sorted(verbs & {"escalate", "bind", "impersonate"})
        if bad:
            yield res.hit(("rules", i, "verbs"), f"{res.label} allows {', '.join(bad)}, which lets the holder obtain permissions it was never granted",
                          "Remove these verbs; only cluster operators that manage RBAC should hold them.")


@rule("K8S3007", "warning", "binding to the default ServiceAccount")
def binds_default_sa(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind not in ("RoleBinding", "ClusterRoleBinding"):
        return
    for i, s in enumerate(as_list(res.get("subjects"))):
        s = as_dict(s)
        if s.get("kind") == "ServiceAccount" and s.get("name") == "default":
            yield res.hit(("subjects", i), f"{res.label} grants permissions to the 'default' ServiceAccount, which every pod without serviceAccountName uses",
                          "Create a dedicated ServiceAccount, bind that, and set it on the workload.")


@rule("K8S3008", "error", "binding to anonymous or unauthenticated users")
def binds_anonymous(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind not in ("RoleBinding", "ClusterRoleBinding"):
        return
    for i, s in enumerate(as_list(res.get("subjects"))):
        s = as_dict(s)
        if s.get("name") in ("system:anonymous", "system:unauthenticated"):
            yield res.hit(("subjects", i), f"{res.label} grants permissions to {s.get('name')}: anyone who can reach the API server, without credentials",
                          "Remove the subject. Anonymous access should be limited to the health endpoints.")


@rule("K8S3009", "warning", "binding to system:authenticated")
def binds_authenticated(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind not in ("RoleBinding", "ClusterRoleBinding"):
        return
    for i, s in enumerate(as_list(res.get("subjects"))):
        s = as_dict(s)
        if s.get("name") == "system:authenticated":
            yield res.hit(("subjects", i), f"{res.label} grants permissions to system:authenticated: every user with any valid credential (on some clouds, any account of the provider)",
                          "Bind a specific group or ServiceAccount.")


@rule("K8S3010", "warning", "role can exec into pods")
def pod_exec(res: Resource, rs: ResourceSet) -> Hits:
    for i, r, verbs, resources, _ in _rules(res):
        if (resources & {"pods/exec", "pods/attach"}) and (verbs & {"create", "get", "*"}):
            yield res.hit(("rules", i), f"{res.label} can run commands inside pods (pods/exec) {_scope(res)}: access to every secret mounted there",
                          "Remove pods/exec and pods/attach from the role, or limit it to a debugging role granted temporarily.")


@rule("K8S3011", "warning", "role can use the nodes/proxy subresource")
def nodes_proxy(res: Resource, rs: ResourceSet) -> Hits:
    for i, r, verbs, resources, _ in _rules(res):
        if "nodes/proxy" in resources and (verbs & {"get", "create", "*"}):
            yield res.hit(("rules", i), f"{res.label} can reach the kubelet API through nodes/proxy, which can execute commands in any pod on the node",
                          "Remove nodes/proxy; use the metrics APIs for monitoring instead.")


def _subjects(res: Resource) -> str:
    out: list[str] = []
    for s in as_list(res.get("subjects")):
        s = as_dict(s)
        ns = f"{s['namespace']}/" if s.get("namespace") else ""
        out.append(f"{s.get('kind')} {ns}{s.get('name')}")
    return ", ".join(out) or "(no subjects)"


def summary(rs: ResourceSet) -> list[str]:
    lines: list[str] = []
    for res in rs.of_kind("ClusterRole", "Role"):
        n = len(as_list(res.get("rules")))
        lines.append(f"{res.kind} {res.name}" + (f" (ns {res.ns})" if res.ns else "") + f": {n} rule(s)  [{res.file.display}:{res.line('kind')}]")
    for res in rs.of_kind("ClusterRoleBinding", "RoleBinding"):
        ref = as_dict(res.get("roleRef"))
        lines.append(f"{res.kind} {res.name}" + (f" (ns {res.ns})" if res.ns else "") + f": {ref.get('kind')} {ref.get('name')} -> {_subjects(res)}")
    return lines
