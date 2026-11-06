"""kubelint-mcp: static Kubernetes manifest linting for AI agents (no cluster, no kubectl)."""

from __future__ import annotations

import argparse
import functools
import os
import sys
from collections.abc import Callable, Sequence
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__
from . import rules_lint, rules_rbac, rules_refs, rules_values  # noqa: F401  (importing registers the rules)
from .errors import UserError
from .explain import explain, find_resource
from .files import Sandbox
from .fixes import suggest
from .helm import render
from .model import ResourceSet, build_set, load_set
from .overview import overview
from .registry import known_ids, run_rules
from .report import clip, format_findings
from .rules_rbac import summary as rbac_summary
from .rules_values import load_values, run_values

mcp = MCPServer(
    "kubelint",
    instructions=(
        "Statically lint and explain Kubernetes manifests. Nothing is applied and no cluster or kubectl is "
        "needed. Pass a YAML file or a directory (relative to the server's --dir, or absolute inside it); "
        "multi-document files and `helm template` output work. Typical flow: k8s_overview to see what is "
        "there, lint_manifests for rule IDs + file:line + concrete fixes, check_references for cross-object "
        "problems (selectors, ingress backends, missing ConfigMaps), rbac_review for permissions, "
        "explain_resource for one object in plain English, suggest_fixes for a diff of the safe fixes, "
        "values_review for a Helm values.yaml. Secret values are never shown. Silence a finding with "
        "`# kubelint-ignore: K8S1004` on the line above."
    ),
)

_sandbox: Sandbox | None = None
_disabled: frozenset[str] = frozenset()

F = TypeVar("F", bound=Callable[..., Any])


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except RecursionError as e:
            raise ToolError("The file is nested too deeply to analyze.") from e
        except (UserError, OSError) as e:
            raise ToolError(str(e)) from e

    mcp.tool()(wrapper)
    return fn


def configure(directory: str | None, disable: Sequence[str] = ()) -> None:
    global _sandbox, _disabled
    _sandbox = Sandbox(directory or os.getcwd())
    ids = known_ids()
    unknown = sorted(d for d in disable if d not in ids)
    if unknown:
        raise UserError(f"unknown rule id(s): {', '.join(unknown)}. Known: {', '.join(sorted(ids))}")
    _disabled = frozenset(disable)


def _sb() -> Sandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = Sandbox(os.getcwd())
    return _sandbox


def _label(path: str, rs: ResourceSet) -> str:
    return f"{path} ({len(rs.resources)} object(s) in {len(rs.files)} file(s))"


@tool
def k8s_overview(path: str) -> str:
    """Summarize Kubernetes manifests: every object by kind and namespace, workloads with replicas,
    images and ports, Services (type, ports, which workloads they select), Ingress routes, and
    host-network workloads. `path` is a YAML file (multi-document is fine, `helm template` output
    works) or a directory of them. Start here, then lint_manifests."""
    rs = load_set(_sb(), path)
    return overview(rs, path)


@tool
def lint_manifests(path: str) -> str:
    """Lint Kubernetes manifests with rules K8S1001-K8S1040: missing resource requests/memory limit,
    :latest or untagged images (and tag-only pins as info), privileged / allowPrivilegeEscalation /
    root user / readOnlyRootFilesystem / capabilities, hostNetwork/hostPID/hostPath/docker.sock,
    missing probes, replicas 1, no PodDisruptionBudget or NetworkPolicy, default namespace, secrets as
    plain env values (name and length only, never the value), service account token, seccomp,
    imagePullPolicy, LoadBalancer/NodePort exposure, CronJob settings, and removed/deprecated apiVersions
    with the replacement and the release that dropped them. Each finding has a rule ID, severity,
    file:line and a concrete fix. Cross-object checks are in check_references, RBAC in rbac_review.
    Suppress with `# kubelint-ignore: K8S1004` above a line. Nothing is applied to any cluster."""
    rs = load_set(_sb(), path)
    found = run_rules(rs, "K8S1", _disabled)
    return format_findings(f"Manifests {_label(path, rs)}", found, rs.lint_note)


@tool
def check_references(path: str) -> str:
    """Cross-resource checks (K8S2001-K8S2017) among the provided files: Deployment selector that does
    not match its template labels (invalid), Service selector matching no pod, targetPort that no
    container declares, Ingress backend Service or port that does not exist, ConfigMap/Secret/PVC/
    ServiceAccount referenced but not defined (info when it may live elsewhere), a key missing from a
    ConfigMap/Secret, HPA or PodDisruptionBudget pointing at nothing, StatefulSet serviceName, volumeMounts
    without a volume, RoleBinding to an undefined Role, and duplicate objects. Pass a directory to check
    a whole app. Only the files you pass are considered."""
    rs = load_set(_sb(), path)
    found = run_rules(rs, "K8S2", _disabled)
    note = "References are resolved only against the provided files; objects without metadata.namespace match any namespace. " + rs.lint_note
    return format_findings(f"References {_label(path, rs)}", found, note.strip())


@tool
def rbac_review(path: str) -> str:
    """Review RBAC (K8S3001-K8S3011): wildcard verbs or resources, ClusterRoleBinding/RoleBinding to
    cluster-admin, read access to Secrets, escalate/bind/impersonate verbs, pods/exec, nodes/proxy, and
    bindings to the default ServiceAccount, system:anonymous, system:unauthenticated or system:authenticated.
    Also lists every Role/ClusterRole and which subjects each binding grants it to."""
    rs = load_set(_sb(), path)
    found = run_rules(rs, "K8S3", _disabled)
    lines = rbac_summary(rs)
    body = format_findings(f"RBAC {_label(path, rs)}", found, rs.lint_note)
    if not lines:
        return body + "\nNo Role, ClusterRole or binding objects were found in these files."
    return clip(body + "\n\nRoles and bindings:\n" + "\n".join("  " + ln for ln in lines))


@tool
def explain_resource(path: str, kind: str, name: str, namespace: str = "") -> str:
    """Explain one object in plain English: what it does, its effective security posture (user, privilege,
    filesystem, capabilities, host access, token, seccomp), what it depends on (ConfigMaps, Secrets, PVCs,
    service account, with whether each is defined in these files), what reaches it (Services, Ingress, HPA,
    PodDisruptionBudget, NetworkPolicy) and its lint findings. `kind` is e.g. Deployment, `name` its
    metadata.name; pass `namespace` if the name exists in several. Env values, ConfigMap/Secret data and
    command arguments are never printed."""
    rs = load_set(_sb(), path)
    res = find_resource(rs, kind, name, namespace)
    found = [f for f in run_rules(rs, "K8S1", _disabled) if f.resource == res.label and f.file == res.file.display]
    found += [f for f in run_rules(rs, "K8S2", _disabled) if f.resource == res.label and f.file == res.file.display]
    found += [f for f in run_rules(rs, "K8S3", _disabled) if f.resource == res.label and f.file == res.file.display]
    return explain(rs, res, found)


@tool
def suggest_fixes(path: str) -> str:
    """Show a unified diff (as text, never written) of the safe mechanical fixes for ONE manifest file:
    privileged / hostNetwork / hostPID / hostIPC set to false, allowPrivilegeEscalation: false added or
    flipped, and apiVersion renames where only the version string changes (batch/v1beta1 CronJob -> batch/v1,
    policy/v1beta1 PodDisruptionBudget -> policy/v1, rbac v1beta1 -> v1, and similar). The patched text is
    re-parsed and re-linted in memory to confirm. Everything else is listed as needing a human decision."""
    sb = _sb()
    real, text = sb.read_text(path)
    if os.path.isdir(real):
        raise UserError("suggest_fixes takes one file, not a directory.")
    display = sb.display(real)
    rs = build_set([(display, text)], False)
    return suggest(rs, text, display, _disabled)


@tool
def values_review(path: str) -> str:
    """Review a Helm values.yaml (K8S4001-K8S4007): :latest or untagged image defaults, resources left empty,
    credentials committed in values (key name and length only, value redacted), empty securityContext,
    Services exposed as LoadBalancer/NodePort by default, replicaCount 1, and insecure defaults like
    privileged or runAsUser 0. Reviews the inputs of a chart; use render_helm or `helm template` output with
    lint_manifests to review what a chart actually produces."""
    sb = _sb()
    real, text = sb.read_text(path)
    vf = load_values(sb.display(real), text)
    found = run_values(vf, _disabled)
    return format_findings(f"Helm values {sb.display(real)}", found, " ".join(vf.notes))


@tool
def render_helm(chart_dir: str, values_file: str = "", release_name: str = "release", namespace: str = "", allow_exec: bool = False) -> str:
    """OPT-IN. Runs the local `helm template` (argument list, 60 s timeout, no cluster contact) on a chart
    directory and lints the rendered output in memory (it is not written anywhere). Refuses unless
    allow_exec=true, so set that only when the user asked to render a chart. Fails with a clear message
    when helm is not installed. `values_file` is an optional values YAML inside --dir."""
    sb = _sb()
    text, label = render(sb, chart_dir, [values_file] if values_file else [], release_name, namespace, allow_exec)
    rs = build_set([("helm template output", text)], False)
    found = run_rules(rs, "K8S1", _disabled)
    return format_findings(f"{label}: {len(rs.resources)} object(s)", found, rs.lint_note)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="kubelint-mcp", description="MCP server that statically lints Kubernetes manifests.")
    p.add_argument("--dir", default=None, help="Only files inside this directory can be read (default: the current directory).")
    p.add_argument("--disable", action="append", default=[], metavar="IDS",
                   help="Comma-separated rule ids to turn off, e.g. K8S1004,K8S1018 (repeatable).")
    p.add_argument("--version", action="version", version=f"kubelint-mcp {__version__}")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = _parse_args(argv)
    ids = [i.strip().upper() for chunk in args.disable for i in chunk.split(",") if i.strip()]
    try:
        configure(args.dir, ids)
    except UserError as e:
        print(f"kubelint-mcp: {e}", file=sys.stderr)
        raise SystemExit(2) from e
    mcp.run()


if __name__ == "__main__":
    main()
