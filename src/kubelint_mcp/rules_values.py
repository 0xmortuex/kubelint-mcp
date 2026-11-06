"""K8S4xxx: review of a Helm values.yaml (the inputs, not the rendered output)."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from .findings import Finding, Hit
from .ignores import IgnoreRange, compute_ignores
from .registry import _ORDER, RULES, RuleInfo
from .rules_lint import parse_image
from .secrets import is_placeholder, is_secret_name, redacted, secret_value_kind, words
from .yamlpos import Doc, Path, load_documents

MAX_WALK = 200_000
_NAME_LIKE = re.compile(r"^[a-z][a-z-]*[a-z]$")


@dataclass
class ValuesFile:
    display: str
    doc: Doc | None
    ignores: list[IgnoreRange]
    problems: list[Hit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def hit(self, path: Path, message: str, fix: str, severity: str | None = None) -> Hit:
        line = self.doc.line(path) if self.doc else 1
        return Hit(self.display, line, "values", message, fix, severity)


def load_values(display: str, text: str) -> ValuesFile:
    lr = load_documents(text)
    vf = ValuesFile(display, lr.docs[0] if lr.docs else None, compute_ignores(text))
    for p in lr.problems:
        vf.problems.append(Hit(display, p.line, "values", p.message, "Fix the YAML syntax at this line.", "error"))
    if len(lr.docs) > 1:
        vf.notes.append("The file has several YAML documents; only the first was reviewed.")
    return vf


def walk(root: Any) -> Iterator[tuple[Path, str, Any, dict[str, Any]]]:
    """Every (path, key, value, parent mapping) in the values tree, depth-first, bounded."""
    stack: list[tuple[Path, Any]] = [((), root)]
    count = 0
    while stack:
        path, node = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                count += 1
                if count > MAX_WALK:
                    return
                kp = path + (k if isinstance(k, str) else str(k),)
                yield kp, str(k), v, node
                stack.append((kp, v))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                stack.append((path + (i,), v))


ValuesFn = Callable[[ValuesFile], Iterator[Hit]]


def _vrule(rule_id: str, severity: str, title: str) -> Callable[[ValuesFn], ValuesFn]:
    def deco(fn: ValuesFn) -> ValuesFn:
        RULES[rule_id] = RuleInfo(rule_id, severity, title, "values", fn)
        return fn

    return deco


@_vrule("K8S4001", "warning", "image tag is latest or missing in values")
def v_image_tag(vf: ValuesFile) -> Iterator[Hit]:
    if vf.doc is None:
        return
    for path, key, value, parent in walk(vf.doc.root):
        if key == "tag" and value == "latest" and ("repository" in parent or "image" in parent or "registry" in parent or "image" in str(path[-2:-1]).lower()):
            yield vf.hit(path, "image.tag is 'latest', a mutable tag", "Pin a release tag (or leave tag empty to use the chart's appVersion) and a digest if the chart supports it.")
        elif key == "image" and isinstance(value, str) and "{{" not in value:
            _, tag, digest = parse_image(value)
            if not digest and tag in (None, "latest"):
                yield vf.hit(path, f"image '{value}' has no pinned tag", "Pin a version tag or digest.")


@_vrule("K8S4002", "info", "resources are not set in values")
def v_resources(vf: ValuesFile) -> Iterator[Hit]:
    if vf.doc is None:
        return
    for path, key, value, _ in walk(vf.doc.root):
        if key == "resources" and (value is None or value == {}):
            yield vf.hit(path, "resources is empty: pods render without requests/limits", "Set resources.requests (cpu, memory) and resources.limits.memory with sensible defaults.")


@_vrule("K8S4003", "error", "secret stored in values")
def v_secrets(vf: ValuesFile) -> Iterator[Hit]:
    if vf.doc is None:
        return
    for path, key, value, _ in walk(vf.doc.root):
        if not isinstance(value, str) or is_placeholder(value):
            continue
        kind = secret_value_kind(value)
        by_name = is_secret_name(key)
        if by_name and words(key)[-1].upper() == "SECRET" and _NAME_LIKE.match(value) and kind is None:
            by_name = False  # a Secret's name (existingSecret: my-secret), not its content
        if by_name and "existing" in key.lower():
            by_name = False
        if by_name or kind:
            why = f" (looks like a {kind})" if kind else ""
            yield vf.hit(path, f"values key {redacted('.'.join(str(p) for p in path), value)} holds a literal credential{why}",
                         "Do not commit credentials in values.yaml: reference an existing Secret (existingSecret) or inject it at deploy time (--set from CI, SOPS, External Secrets).")


@_vrule("K8S4004", "info", "empty securityContext in values")
def v_security_context(vf: ValuesFile) -> Iterator[Hit]:
    if vf.doc is None:
        return
    for path, key, value, _ in walk(vf.doc.root):
        if key in ("securityContext", "podSecurityContext") and (value is None or value == {}):
            yield vf.hit(path, f"{key} is empty: the chart applies no security hardening by default", "Default to runAsNonRoot: true, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities.drop: [ALL].")


@_vrule("K8S4005", "warning", "Service exposed publicly by default")
def v_service_type(vf: ValuesFile) -> Iterator[Hit]:
    if vf.doc is None:
        return
    for path, key, value, parent in walk(vf.doc.root):
        if key == "type" and value in ("LoadBalancer", "NodePort") and path[-2:-1] and str(path[-2]).lower().startswith("service"):
            yield vf.hit(path, f"service.type defaults to {value}, exposing the app outside the cluster for every install",
                         "Default to ClusterIP; let users opt in to LoadBalancer/NodePort or an Ingress.", "warning" if value == "LoadBalancer" else "info")


@_vrule("K8S4006", "info", "replicaCount is 1")
def v_replicas(vf: ValuesFile) -> Iterator[Hit]:
    if vf.doc is None:
        return
    for path, key, value, _ in walk(vf.doc.root):
        if key in ("replicaCount", "replicas") and isinstance(value, int) and not isinstance(value, bool) and value == 1 and len(path) == 1:
            yield vf.hit(path, f"{key}: 1 means a single point of failure", f"Default to {key}: 2 or more for anything that serves traffic.")


@_vrule("K8S4007", "warning", "insecure security setting in values")
def v_insecure(vf: ValuesFile) -> Iterator[Hit]:
    if vf.doc is None:
        return
    for path, key, value, _ in walk(vf.doc.root):
        if (key in ("privileged", "hostNetwork", "hostPID", "hostIPC") and value is True) or (key == "runAsUser" and value == 0 and not isinstance(value, bool)) or (key == "runAsNonRoot" and value is False):
            yield vf.hit(path, f"{key}: {str(value).lower()} is set as the default", "Default to the safe value and let operators override it explicitly.")


def run_values(vf: ValuesFile, disabled: frozenset[str]) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()
    for h in vf.problems:
        if "K8S1000" not in disabled:
            out.append(Finding("K8S1000", "error", h.file, h.line, h.resource, h.message, h.fix))
    for info in RULES.values():
        if info.scope != "values" or info.id in disabled:
            continue
        for h in info.fn(vf):
            key = (info.id, h.line, h.message)
            if key in seen or any(r.covers(info.id, h.line) for r in vf.ignores):
                continue
            seen.add(key)
            out.append(Finding(info.id, h.severity or info.severity, h.file, h.line, h.resource, h.message, h.fix))
    out.sort(key=lambda f: (f.line, _ORDER.get(f.severity, 9), f.rule))
    return out

