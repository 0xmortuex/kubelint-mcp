"""Resources, pod specs and label selectors, built from the position-tracking loader."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from .errors import UserError, shorten
from .files import MAX_TOTAL_BYTES, Sandbox, read_real
from .findings import Hit
from .ignores import IgnoreIndex, IgnoreRange, compute_ignores
from .yamlpos import Doc, LoadResult, Path, load_documents

MAX_RESOURCES = 5000

NAMESPACED = frozenset({
    "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob",
    "Service", "ConfigMap", "Secret", "PersistentVolumeClaim", "ServiceAccount", "Ingress", "NetworkPolicy",
    "PodDisruptionBudget", "HorizontalPodAutoscaler", "Role", "RoleBinding", "Endpoints", "LimitRange",
    "ResourceQuota",
})
KNOWN_KINDS = NAMESPACED | frozenset({
    "Namespace", "ClusterRole", "ClusterRoleBinding", "PersistentVolume", "StorageClass", "IngressClass",
    "CustomResourceDefinition", "PriorityClass", "Node", "MutatingWebhookConfiguration",
    "ValidatingWebhookConfiguration", "APIService", "List",
})
# Kinds that own a pod template, and where the pod spec sits inside them.
POD_SPEC_PATH: dict[str, Path] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "ReplicationController": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}
CONTROLLERS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController"})
LONG_RUNNING = CONTROLLERS | {"Pod"}


def dig(obj: Any, *path: Any) -> Any:
    for p in path:
        if isinstance(obj, dict):
            obj = obj.get(p)
        elif isinstance(obj, list) and isinstance(p, int) and 0 <= p < len(obj):
            obj = obj[p]
        else:
            return None
    return obj


def as_dict(x: Any) -> dict[str, Any]:
    return x if isinstance(x, dict) else {}


def as_list(x: Any) -> list[Any]:
    return x if isinstance(x, list) else []


def str_or_none(x: Any) -> str | None:
    return x if isinstance(x, str) and x else None


@dataclass
class SourceFile:
    display: str
    text: str
    docs: list[Doc] = field(default_factory=list)
    ignores: list[IgnoreRange] = field(default_factory=list)
    truncated: bool = False

    def __post_init__(self) -> None:
        self.ignore_index = IgnoreIndex(self.ignores)


@dataclass(eq=False)
class Resource:
    file: SourceFile
    doc: Doc
    base: Path
    obj: dict[str, Any]
    api: str
    kind: str
    name: str
    ns: str | None

    @property
    def label(self) -> str:
        return f"{self.kind}/{self.name}"

    @property
    def group(self) -> str:
        return self.api.split("/")[0] if "/" in self.api else ""

    def line(self, *path: Any) -> int:
        return self.doc.line(self.base + path)

    def get(self, *path: Any) -> Any:
        return dig(self.obj, *path)

    def hit(self, path: tuple[Any, ...], message: str, fix: str, severity: str | None = None) -> Hit:
        if not path:
            path = ("kind",)
        return Hit(self.file.display, self.line(*path), self.label, message, fix, severity)


@dataclass
class Container:
    path: Path  # relative to the resource root
    data: dict[str, Any]
    init: bool

    @property
    def name(self) -> str:
        n = self.data.get("name")
        return n if isinstance(n, str) and n else "<unnamed>"


@dataclass
class PodView:
    res: Resource
    path: Path  # path of the pod spec, relative to the resource root
    spec: dict[str, Any]

    @property
    def template_labels(self) -> dict[str, str]:
        if self.res.kind == "Pod":
            lab = self.res.get("metadata", "labels")
        else:
            lab = dig(self.res.obj, *self.path[:-1], "metadata", "labels")
        return {str(k): str(v) for k, v in as_dict(lab).items()}

    def containers(self, init: bool = True) -> list[Container]:
        out: list[Container] = []
        for i, c in enumerate(as_list(self.spec.get("containers"))):
            if isinstance(c, dict):
                out.append(Container(self.path + ("containers", i), c, False))
        if init:
            for i, c in enumerate(as_list(self.spec.get("initContainers"))):
                if isinstance(c, dict):
                    out.append(Container(self.path + ("initContainers", i), c, True))
        return out


def pod_view(res: Resource) -> PodView | None:
    path = POD_SPEC_PATH.get(res.kind)
    if path is None:
        return None
    spec = dig(res.obj, *path)
    return PodView(res, path, spec) if isinstance(spec, dict) else None


# ---------------------------------------------------------------- selectors


def map_selector_matches(selector: Any, labels: dict[str, str]) -> bool:
    """Equality selector as used by Service.spec.selector. An empty selector selects nothing."""
    if not isinstance(selector, dict) or not selector:
        return False
    return all(str(labels.get(str(k))) == str(v) and str(k) in labels for k, v in selector.items())


def label_selector_matches(selector: Any, labels: dict[str, str]) -> bool:
    """metav1.LabelSelector (matchLabels + matchExpressions). An empty selector matches everything."""
    if not isinstance(selector, dict):
        return False
    for k, v in as_dict(selector.get("matchLabels")).items():
        if str(k) not in labels or labels[str(k)] != str(v):
            return False
    for expr in as_list(selector.get("matchExpressions")):
        if not isinstance(expr, dict):
            return False
        key = str(expr.get("key"))
        op = expr.get("operator")
        vals = {str(v) for v in as_list(expr.get("values"))}
        if op == "In" and not (key in labels and labels[key] in vals):
            return False
        if op == "NotIn" and key in labels and labels[key] in vals:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


def ns_match(a: str | None, b: str | None) -> bool:
    """A resource without metadata.namespace lands in whatever namespace it is applied to, so it matches any."""
    return a is None or b is None or a == b


# ---------------------------------------------------------------- the set of resources


@dataclass
class ResourceSet:
    files: list[SourceFile] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)
    load_hits: list[Hit] = field(default_factory=list)  # K8S1000, K8S1039 are produced from these
    unknown_kinds: Counter[str] = field(default_factory=Counter)
    skipped_non_k8s: int = 0
    helm_templates: int = 0
    notes: list[str] = field(default_factory=list)
    _by_kind: dict[str, list[Resource]] = field(default_factory=dict)

    def add(self, res: Resource) -> None:
        self.resources.append(res)
        self._by_kind.setdefault(res.kind, []).append(res)

    def of_kind(self, *kinds: str) -> list[Resource]:
        out: list[Resource] = []
        for k in kinds:
            out.extend(self._by_kind.get(k, []))
        return out

    def find(self, kind: str, name: str, ns: str | None) -> Resource | None:
        for r in self._by_kind.get(kind, []):
            if r.name == name and ns_match(r.ns, ns):
                return r
        return None

    def workloads(self) -> Iterator[PodView]:
        for r in self.resources:
            pv = pod_view(r)
            if pv is not None:
                yield pv

    @property
    def lint_note(self) -> str:
        parts: list[str] = []
        if self.unknown_kinds:
            kinds = ", ".join(f"{k} x{n}" for k, n in sorted(self.unknown_kinds.items()))
            parts.append(
                f"{sum(self.unknown_kinds.values())} object(s) of kinds with no lint rules were skipped quietly "
                f"(custom resources and others): {kinds}."
            )
        if self.skipped_non_k8s:
            parts.append(f"{self.skipped_non_k8s} YAML document(s) without apiVersion/kind were skipped (not Kubernetes objects).")
        if self.helm_templates:
            parts.append(
                f"{self.helm_templates} file(s) look like unrendered Helm templates ({{{{ }}}}) and were skipped; "
                "run `helm template` and lint its output, or use render_helm."
            )
        parts.extend(self.notes)
        return " ".join(parts)


def _res_name(obj: dict[str, Any]) -> str:
    md = as_dict(obj.get("metadata"))
    name = md.get("name")
    if isinstance(name, str) and name:
        return name
    gen = md.get("generateName")
    if isinstance(gen, str) and gen:
        return gen + "*"
    return "<unnamed>"


def _add_doc(rs: ResourceSet, sf: SourceFile, doc: Doc, directory_mode: bool) -> None:
    root = doc.root
    if root is None:
        return
    if not isinstance(root, dict):
        rs.load_hits.append(Hit(sf.display, doc.start_line, "document", "document is not a mapping, so it is not a Kubernetes object",
                                "Each YAML document must be a mapping with apiVersion, kind and metadata.", "error"))
        return
    kind, api = root.get("kind"), root.get("apiVersion")
    if kind is None and api is None:
        if directory_mode:
            rs.skipped_non_k8s += 1
        else:
            rs.load_hits.append(Hit(sf.display, doc.start_line, "document", "document has no apiVersion or kind",
                                    "Add apiVersion and kind, or drop this document if it is not a Kubernetes object.", "warning"))
        return
    if not isinstance(kind, str) or not isinstance(api, str):
        rs.load_hits.append(Hit(sf.display, doc.line(("kind",)) if "kind" in root else doc.start_line, "document",
                                "apiVersion and kind must both be strings",
                                "Set apiVersion (for example apps/v1) and kind (for example Deployment).", "error"))
        return
    for dpath, key, line in doc.dups:
        rs.load_hits.append(Hit(sf.display, line, f"{kind}/{_res_name(root)}",
                                f"duplicate mapping key '{key}': YAML silently keeps only the last one",
                                "Remove or merge the duplicate key.", "error"))

    def put(obj: dict[str, Any], base: Path) -> None:
        if len(rs.resources) >= MAX_RESOURCES:
            if "resource cap" not in " ".join(rs.notes):
                rs.notes.append(f"Stopped after {MAX_RESOURCES} objects (resource cap).")
            return
        k, a = obj.get("kind"), obj.get("apiVersion")
        if not isinstance(k, str) or not isinstance(a, str):
            rs.load_hits.append(Hit(sf.display, doc.line(base), "List item", "list item needs string apiVersion and kind",
                                    "Give every item of a List an apiVersion and kind.", "error"))
            return
        md = as_dict(obj.get("metadata"))
        ns = md.get("namespace")
        res = Resource(sf, doc, base, obj, a, k, _res_name(obj), ns if isinstance(ns, str) and ns else None)
        if k not in KNOWN_KINDS and not k.endswith("List"):
            rs.unknown_kinds[k] += 1
        rs.add(res)

    if kind.endswith("List") and isinstance(root.get("items"), list):
        for i, item in enumerate(as_list(root.get("items"))):
            if isinstance(item, dict):
                put(item, ("items", i))
        return
    put(root, ())


def build_set(sources: list[tuple[str, str]], directory_mode: bool) -> ResourceSet:
    """sources: (display name, text). Parses every file and gathers resources and parse problems."""
    rs = ResourceSet()
    for display, text in sources:
        lr: LoadResult = load_documents(text)
        if directory_mode and lr.problems and "{{" in text:
            rs.helm_templates += 1
            continue
        sf = SourceFile(display, text, lr.docs, compute_ignores(text), lr.truncated)
        rs.files.append(sf)
        for p in lr.problems:
            msg = p.message
            fix = "Fix the YAML syntax at this line; the rest of the file after it was not analyzed."
            if "{{" in text:
                fix = "This looks like an unrendered Helm template. Run `helm template` and lint its output."
            rs.load_hits.append(Hit(display, p.line, "document", msg, fix, "error"))
        if lr.truncated:
            rs.notes.append(f"{display}: more than 1000 documents; the rest were not analyzed.")
        for doc in lr.docs:
            _add_doc(rs, sf, doc, directory_mode)
    return rs


def load_set(sb: Sandbox, path: str) -> ResourceSet:
    paths, is_dir, truncated = sb.collect(path)
    sources: list[tuple[str, str]] = []
    total = 0
    for real in paths:
        text = read_real(real, sb.display(real))
        total += len(text)
        if total > MAX_TOTAL_BYTES:
            raise UserError(f"{shorten(path)!r} holds more than {MAX_TOTAL_BYTES} bytes of YAML; point at a smaller directory.")
        sources.append((sb.display(real), text))
    rs = build_set(sources, is_dir)
    if truncated:
        rs.notes.append("More YAML files than the cap allows; only the first 300 were read.")
    return rs

