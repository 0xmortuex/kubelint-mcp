"""Rule registry and the engine that runs rules, applies --disable and kubelint-ignore comments."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .findings import Finding, Hit
from .model import Resource, ResourceSet

SEVERITIES = ("error", "warning", "info")
_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class RuleInfo:
    id: str
    severity: str
    title: str
    scope: str  # "resource": fn(res, rs); "set": fn(rs)
    fn: Callable[..., Iterable[Hit]]


RULES: dict[str, RuleInfo] = {}


def rule(rule_id: str, severity: str, title: str, scope: str = "resource") -> Callable[[Callable[..., Iterable[Hit]]], Callable[..., Iterable[Hit]]]:
    def deco(fn: Callable[..., Iterable[Hit]]) -> Callable[..., Iterable[Hit]]:
        if rule_id in RULES:
            raise RuntimeError(f"duplicate rule id {rule_id}")
        RULES[rule_id] = RuleInfo(rule_id, severity, title, scope, fn)
        return fn

    return deco


# Pseudo-rules produced by the loader rather than a rule function.
LOADER_RULES = {
    "K8S1000": ("error", "YAML or document-structure problem"),
    "K8S1039": ("error", "duplicate mapping key"),
}


def known_ids() -> set[str]:
    return set(RULES) | set(LOADER_RULES)


def run_rules(rs: ResourceSet, prefix: str, disabled: frozenset[str], only: Resource | None = None) -> list[Finding]:
    """Run every rule whose id starts with `prefix` (e.g. "K8S1"). `only` restricts to one resource."""
    out: list[Finding] = []
    seen: set[tuple[str, str, int, str]] = set()
    files = {sf.display: sf for sf in rs.files}

    def emit(rid: str, sev_default: str, hit: Hit) -> None:
        if rid in disabled:
            return
        sev = hit.severity or sev_default
        key = (rid, hit.file, hit.line, hit.message)
        sf = files.get(hit.file)
        if key in seen or (sf is not None and sf.ignore_index.covers(rid, hit.line)):
            return
        seen.add(key)
        out.append(Finding(rid, sev, hit.file, hit.line, hit.resource, hit.message, hit.fix))

    if prefix == "K8S1":
        for h in rs.load_hits:
            rid = "K8S1039" if h.message.startswith("duplicate mapping key") else "K8S1000"
            if only is None or h.resource == only.label:
                emit(rid, LOADER_RULES[rid][0], h)
    for info in RULES.values():
        if not info.id.startswith(prefix):
            continue
        if info.scope == "set":
            for h in info.fn(rs):
                if only is None or h.resource == only.label:
                    emit(info.id, info.severity, h)
        else:
            for res in rs.resources if only is None else [only]:
                for h in info.fn(res, rs):
                    emit(info.id, info.severity, h)
    out.sort(key=lambda f: (f.file, f.line, _ORDER.get(f.severity, 9), f.rule))
    return out
