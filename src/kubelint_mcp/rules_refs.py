"""K8S2xxx: cross-resource reference checks (only against the files that were provided)."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from .findings import Hit
from .model import (
    CONTROLLERS,
    PodView,
    Resource,
    ResourceSet,
    as_dict,
    as_list,
    label_selector_matches,
    map_selector_matches,
    ns_match,
    pod_view,
)
from .registry import rule
from .yamlpos import Path

Hits = Iterator[Hit]

BUILTIN_CLUSTER_ROLES = {"cluster-admin", "admin", "edit", "view"}


@dataclass
class Ref:
    kind: str  # ConfigMap, Secret, PersistentVolumeClaim, ServiceAccount
    name: str
    key: str | None
    optional: bool
    path: Path  # relative to the resource root


def pod_refs(pv: PodView) -> Iterator[Ref]:
    spec = pv.spec
    for c in pv.containers():
        for i, e in enumerate(as_list(c.data.get("env"))):
            vf = as_dict(as_dict(e).get("valueFrom"))
            for field_name, kind in (("configMapKeyRef", "ConfigMap"), ("secretKeyRef", "Secret")):
                ref = as_dict(vf.get(field_name))
                if isinstance(ref.get("name"), str):
                    yield Ref(kind, ref["name"], ref.get("key") if isinstance(ref.get("key"), str) else None,
                              ref.get("optional") is True, c.path + ("env", i, "valueFrom", field_name))
        for i, ef in enumerate(as_list(c.data.get("envFrom"))):
            for field_name, kind in (("configMapRef", "ConfigMap"), ("secretRef", "Secret")):
                ref = as_dict(as_dict(ef).get(field_name))
                if isinstance(ref.get("name"), str):
                    yield Ref(kind, ref["name"], None, ref.get("optional") is True, c.path + ("envFrom", i, field_name))
    for i, v in enumerate(as_list(spec.get("volumes"))):
        v = as_dict(v)
        base = pv.path + ("volumes", i)
        cm = as_dict(v.get("configMap"))
        if isinstance(cm.get("name"), str):
            yield Ref("ConfigMap", cm["name"], None, cm.get("optional") is True, base + ("configMap",))
            for j, it in enumerate(as_list(cm.get("items"))):
                k = as_dict(it).get("key")
                if isinstance(k, str):
                    yield Ref("ConfigMap", cm["name"], k, cm.get("optional") is True, base + ("configMap", "items", j))
        sec = as_dict(v.get("secret"))
        if isinstance(sec.get("secretName"), str):
            yield Ref("Secret", sec["secretName"], None, sec.get("optional") is True, base + ("secret",))
            for j, it in enumerate(as_list(sec.get("items"))):
                k = as_dict(it).get("key")
                if isinstance(k, str):
                    yield Ref("Secret", sec["secretName"], k, sec.get("optional") is True, base + ("secret", "items", j))
        pvc = as_dict(v.get("persistentVolumeClaim"))
        if isinstance(pvc.get("claimName"), str):
            yield Ref("PersistentVolumeClaim", pvc["claimName"], None, False, base + ("persistentVolumeClaim",))
        for j, src in enumerate(as_list(as_dict(v.get("projected")).get("sources"))):
            src = as_dict(src)
            for field_name, kind in (("configMap", "ConfigMap"), ("secret", "Secret")):
                ref = as_dict(src.get(field_name))
                if isinstance(ref.get("name"), str):
                    yield Ref(kind, ref["name"], None, ref.get("optional") is True, base + ("projected", "sources", j, field_name))
    for i, ips in enumerate(as_list(spec.get("imagePullSecrets"))):
        n = as_dict(ips).get("name")
        if isinstance(n, str):
            yield Ref("Secret", n, None, False, pv.path + ("imagePullSecrets", i))
    sa = spec.get("serviceAccountName")
    if isinstance(sa, str) and sa != "default":
        yield Ref("ServiceAccount", sa, None, False, pv.path + ("serviceAccountName",))


def selected_pods(svc: Resource, rs: ResourceSet) -> list[PodView]:
    sel = svc.get("spec", "selector")
    return [pv for pv in rs.workloads() if ns_match(pv.res.ns, svc.ns) and map_selector_matches(sel, pv.template_labels)]


def _declared_keys(obj: Resource) -> set[str] | None:
    keys: set[str] = set()
    found = False
    for section in ("data", "binaryData", "stringData"):
        sec = obj.get(section)
        if isinstance(sec, dict):
            found = True
            keys.update(str(k) for k in sec)
    return keys if found else None


def produced_secrets(rs: ResourceSet) -> set[str]:
    """Names of Secrets that a controller in the provided files creates: cert-manager Certificate (spec.secretName),
    ExternalSecret (spec.target.name or its own name) and SealedSecret (its own name)."""
    names: set[str] = set()
    for r in rs.of_kind("Certificate"):
        n = r.get("spec", "secretName")
        if isinstance(n, str):
            names.add(n)
    for r in rs.of_kind("ExternalSecret"):
        n = r.get("spec", "target", "name")
        names.add(n if isinstance(n, str) else r.name)
    for r in rs.of_kind("SealedSecret"):
        n = r.get("spec", "template", "metadata", "name")
        names.add(n if isinstance(n, str) else r.name)
    return names


def _missing(res: Resource, rs: ResourceSet, kind: str) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for ref in pod_refs(pv):
        if ref.kind != kind or ref.optional:
            continue
        target = rs.find(kind, ref.name, res.ns)
        if target is None and kind == "Secret" and ref.name in produced_secrets(rs):
            continue
        if target is None:
            elsewhere = any(ns_match(r.ns, res.ns) for r in rs.of_kind(kind))
            if kind == "Secret" or kind == "ServiceAccount":
                sev = "info"
            else:
                sev = "warning" if elsewhere else "info"
            note = "" if sev == "warning" else " (it may be defined elsewhere, for example another file, Helm hook or created out-of-band)"
            yield res.hit(ref.path, f"{res.label} references {kind} '{ref.name}', which is not defined in the provided files{note}",
                          f"Add the {kind} to the manifests, or fix the name. Mark the reference optional: true if it may legitimately be absent.", sev)


@rule("K8S2005", "warning", "ConfigMap referenced but not defined")
def missing_configmap(res: Resource, rs: ResourceSet) -> Hits:
    return _missing(res, rs, "ConfigMap")


@rule("K8S2006", "info", "Secret referenced but not defined")
def missing_secret(res: Resource, rs: ResourceSet) -> Hits:
    return _missing(res, rs, "Secret")


@rule("K8S2007", "warning", "PersistentVolumeClaim referenced but not defined")
def missing_pvc(res: Resource, rs: ResourceSet) -> Hits:
    return _missing(res, rs, "PersistentVolumeClaim")


@rule("K8S2008", "info", "ServiceAccount referenced but not defined")
def missing_sa(res: Resource, rs: ResourceSet) -> Hits:
    return _missing(res, rs, "ServiceAccount")


@rule("K8S2009", "error", "key not present in the referenced ConfigMap/Secret")
def missing_key(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for ref in pod_refs(pv):
        if ref.key is None or ref.optional or ref.kind not in ("ConfigMap", "Secret"):
            continue
        target = rs.find(ref.kind, ref.name, res.ns)
        if target is None:
            continue
        keys = _declared_keys(target)
        if keys is not None and ref.key not in keys:
            yield res.hit(ref.path, f"{res.label} reads key '{ref.key}' of {ref.kind} '{ref.name}' ({target.file.display}:{target.line('kind')}), which has no such key",
                          f"Add '{ref.key}' to the {ref.kind}, or correct the key name (available: {', '.join(sorted(keys)) or 'none'}).")


# ------------------------------------------------------------------ workload selectors


@rule("K8S2001", "error", "selector does not match the pod template labels")
def selector_mismatch(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind not in CONTROLLERS:
        return
    spec = as_dict(res.get("spec"))
    tmpl_labels = {str(k): str(v) for k, v in as_dict(as_dict(as_dict(spec.get("template")).get("metadata")).get("labels")).items()}
    sel = spec.get("selector")
    if sel is None:
        if res.api.startswith("apps/") or res.kind == "ReplicaSet":
            yield res.hit(("spec",), f"{res.label} has no spec.selector, which is required in {res.api}",
                          "Add spec.selector.matchLabels with labels that the pod template also carries.")
        return
    if res.kind == "ReplicationController":
        if sel and not map_selector_matches(sel, tmpl_labels):
            yield res.hit(("spec", "selector"), f"{res.label} selector {dict(sel)} does not match its template labels {tmpl_labels}",
                          "Make the template labels a superset of the selector.")
        return
    if not label_selector_matches(sel, tmpl_labels):
        yield res.hit(("spec", "selector"),
                      f"{res.label} selector {_fmt_selector(sel)} does not match the pod template labels {tmpl_labels or '{}'}; the API server rejects this object",
                      "Make spec.template.metadata.labels include every label in spec.selector (and never change the selector later: it is immutable).")


def _fmt_selector(sel: Any) -> str:
    sel = as_dict(sel)
    parts = [f"{k}={v}" for k, v in as_dict(sel.get("matchLabels")).items()]
    parts += [f"{as_dict(e).get('key')} {as_dict(e).get('operator')} {as_list(as_dict(e).get('values'))}" for e in as_list(sel.get("matchExpressions"))]
    return "{" + ", ".join(parts) + "}"


# ------------------------------------------------------------------ services


@rule("K8S2002", "warning", "Service selector matches no pod template")
def service_selects_nothing(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "Service" or res.get("spec", "type") == "ExternalName":
        return
    sel = res.get("spec", "selector")
    if not isinstance(sel, dict) or not sel:
        return
    if selected_pods(res, rs):
        return
    any_workloads = any(ns_match(pv.res.ns, res.ns) for pv in rs.workloads())
    yield res.hit(("spec", "selector"),
                  f"Service '{res.name}' selects {dict(sel)}, which no pod template in the provided files carries"
                  + ("" if any_workloads else " (no workloads were provided in this namespace, so the pods may be defined elsewhere)"),
                  "Make the selector equal to labels on the pod template (spec.template.metadata.labels), not on the Deployment's own metadata.",
                  "warning" if any_workloads else "info")


@rule("K8S2010", "warning", "Service targetPort does not match a container port")
def target_port(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "Service" or res.get("spec", "type") == "ExternalName":
        return
    pods = selected_pods(res, rs)
    if not pods:
        return
    names: set[str] = set()
    numbers: set[int] = set()
    for pv in pods:
        for c in pv.containers(init=False):
            for p in as_list(c.data.get("ports")):
                p = as_dict(p)
                if isinstance(p.get("name"), str):
                    names.add(p["name"])
                if isinstance(p.get("containerPort"), int):
                    numbers.add(p["containerPort"])
    for i, sp in enumerate(as_list(res.get("spec", "ports"))):
        sp = as_dict(sp)
        tp = sp.get("targetPort", sp.get("port"))
        if isinstance(tp, str):
            if tp not in names:
                yield res.hit(("spec", "ports", i), f"Service '{res.name}' targets the named port '{tp}', but no selected container declares a port with that name",
                              f"Name the containerPort '{tp}' in the pod template (ports: [{{name: {tp}, containerPort: <n>}}]) or use the number.", "error")
        elif isinstance(tp, int) and not isinstance(tp, bool) and numbers and tp not in numbers:
            yield res.hit(("spec", "ports", i), f"Service '{res.name}' targets port {tp}, but the selected containers declare {sorted(numbers)}",
                          f"Set targetPort to one of {sorted(numbers)}, or add containerPort {tp} if the app listens there.")


@rule("K8S2016", "error", "Service with several ports needs port names")
def service_port_names(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "Service":
        return
    ports = as_list(res.get("spec", "ports"))
    if len(ports) > 1:
        for i, p in enumerate(ports):
            if not as_dict(p).get("name"):
                yield res.hit(("spec", "ports", i), f"Service '{res.name}' has {len(ports)} ports but this one has no name; the API server rejects it",
                              "Give every port of a multi-port Service a unique DNS-label name.")


# ------------------------------------------------------------------ ingress


def _ingress_backends(res: Resource) -> Iterator[tuple[Path, str, int | str | None]]:
    spec = as_dict(res.get("spec"))

    def one(path: Path, backend: Any) -> Iterator[tuple[Path, str, int | str | None]]:
        b = as_dict(backend)
        svc = as_dict(b.get("service"))
        if isinstance(svc.get("name"), str):
            port = as_dict(svc.get("port"))
            yield path, svc["name"], port.get("number", port.get("name"))
        elif isinstance(b.get("serviceName"), str):
            yield path, b["serviceName"], b.get("servicePort")

    yield from one(("spec", "defaultBackend"), spec.get("defaultBackend", spec.get("backend")))
    for ri, r in enumerate(as_list(spec.get("rules"))):
        for pi, p in enumerate(as_list(as_dict(as_dict(r).get("http")).get("paths"))):
            yield from one(("spec", "rules", ri, "http", "paths", pi, "backend"), as_dict(p).get("backend"))


@rule("K8S2003", "warning", "Ingress backend Service not found")
def ingress_service(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "Ingress":
        return
    for path, svc_name, _ in _ingress_backends(res):
        if rs.find("Service", svc_name, res.ns) is None:
            has_services = any(ns_match(s.ns, res.ns) for s in rs.of_kind("Service"))
            yield res.hit(path, f"Ingress '{res.name}' routes to Service '{svc_name}', which is not defined in the provided files"
                          + ("" if has_services else " (no Services at all were provided, so it may live elsewhere)"),
                          "Define the Service, or fix backend.service.name.", "warning" if has_services else "info")


@rule("K8S2004", "error", "Ingress backend port not exposed by the Service")
def ingress_port(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "Ingress":
        return
    for path, svc_name, port in _ingress_backends(res):
        svc = rs.find("Service", svc_name, res.ns)
        if svc is None or port is None:
            continue
        ports = [as_dict(p) for p in as_list(svc.get("spec", "ports"))]
        ok = any((isinstance(port, int) and p.get("port") == port) or (isinstance(port, str) and p.get("name") == port) for p in ports)
        if not ok:
            have = [p.get("name") or p.get("port") for p in ports]
            yield res.hit(path, f"Ingress '{res.name}' routes to port {port!r} of Service '{svc_name}', which exposes {have}",
                          "Use a port number or name that the Service lists under spec.ports.")


# ------------------------------------------------------------------ autoscaling, budgets, statefulsets, rbac


@rule("K8S2011", "warning", "HorizontalPodAutoscaler target not found")
def hpa_target(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "HorizontalPodAutoscaler":
        return
    ref = as_dict(res.get("spec", "scaleTargetRef"))
    kind, name = ref.get("kind"), ref.get("name")
    if isinstance(kind, str) and isinstance(name, str) and rs.find(kind, name, res.ns) is None:
        yield res.hit(("spec", "scaleTargetRef"), f"HPA '{res.name}' scales {kind} '{name}', which is not defined in the provided files",
                      "Point scaleTargetRef at an existing Deployment/StatefulSet (same namespace).")


@rule("K8S2012", "warning", "PodDisruptionBudget selects no workload")
def pdb_selects_nothing(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "PodDisruptionBudget":
        return
    pods = [pv for pv in rs.workloads() if ns_match(pv.res.ns, res.ns)]
    if not pods:
        return
    sel = res.get("spec", "selector")
    if sel is None:
        return
    if not any(label_selector_matches(sel, pv.template_labels) for pv in pods):
        yield res.hit(("spec", "selector"), f"PodDisruptionBudget '{res.name}' selector {_fmt_selector(sel)} matches no pod template in the provided files",
                      "Use the same labels as the workload's pod template.")


@rule("K8S2013", "error", "duplicate resource", scope="set")
def duplicates(rs: ResourceSet) -> Hits:
    seen: dict[tuple[str, str, str, str], Resource] = {}
    for res in rs.resources:
        if res.name == "<unnamed>" or res.name.endswith("*"):
            continue
        key = (res.group, res.kind, res.ns or "", res.name)
        first = seen.get(key)
        if first is None:
            seen[key] = res
            continue
        yield res.hit(("metadata", "name"), f"{res.label} is defined twice (first at {first.file.display}:{first.line('metadata', 'name')}); the later one overwrites the earlier on apply",
                      "Remove one of the definitions or give it a different name/namespace.")


@rule("K8S2014", "warning", "StatefulSet serviceName not found")
def statefulset_service(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "StatefulSet":
        return
    name = res.get("spec", "serviceName")
    if isinstance(name, str) and name and rs.find("Service", name, res.ns) is None:
        yield res.hit(("spec", "serviceName"), f"StatefulSet '{res.name}' uses serviceName '{name}', but no such Service is defined in the provided files",
                      "Define the (usually headless: clusterIP: None) Service that gives the pods stable DNS names.")


@rule("K8S2015", "warning", "binding refers to a Role that is not defined")
def binding_role(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind not in ("RoleBinding", "ClusterRoleBinding"):
        return
    ref = as_dict(res.get("roleRef"))
    kind, name = ref.get("kind"), ref.get("name")
    if not isinstance(kind, str) or not isinstance(name, str):
        yield res.hit(("roleRef",), f"{res.label} has no valid roleRef (kind and name are required)", "Add roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role|ClusterRole, name: <name>}.", "error")
        return
    if kind == "ClusterRole" and (name in BUILTIN_CLUSTER_ROLES or name.startswith("system:")):
        return
    ns = res.ns if kind == "Role" else None
    if rs.find(kind, name, ns) is None:
        sev = "warning" if kind == "Role" else "info"
        yield res.hit(("roleRef",), f"{res.label} binds {kind} '{name}', which is not defined in the provided files",
                      f"Define the {kind}, or fix roleRef.name.", sev)


@rule("K8S2017", "error", "volumeMount refers to a volume that is not declared")
def volume_mount_unknown(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    declared = {as_dict(v).get("name") for v in as_list(pv.spec.get("volumes"))}
    for t in as_list(res.get("spec", "volumeClaimTemplates")):
        declared.add(as_dict(as_dict(t).get("metadata")).get("name"))
    for c in pv.containers():
        for i, m in enumerate(as_list(c.data.get("volumeMounts"))):
            n = as_dict(m).get("name")
            if isinstance(n, str) and n not in declared:
                yield res.hit(c.path + ("volumeMounts", i), f"container '{c.name}' mounts volume '{n}', which is not declared in spec.volumes; the pod is rejected",
                              f"Declare a volume named '{n}' under spec.volumes, or fix the mount name.")
