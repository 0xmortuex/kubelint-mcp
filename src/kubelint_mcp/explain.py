"""explain_resource: a plain-English account of one object. Never prints env values, command arguments,
ConfigMap data or Secret data: names and counts only."""

from __future__ import annotations

from collections import Counter

from .errors import UserError, shorten
from .findings import Finding
from .model import (
    Container,
    PodView,
    Resource,
    ResourceSet,
    as_dict,
    as_list,
    dig,
    label_selector_matches,
    map_selector_matches,
    ns_match,
    pod_view,
)
from .report import clip
from .rules_lint import parse_image
from .rules_refs import _ingress_backends, pod_refs, selected_pods


def find_resource(rs: ResourceSet, kind: str, name: str, namespace: str) -> Resource:
    k = kind.strip().lower()
    cands = [r for r in rs.resources if r.kind.lower() == k and r.name == name]
    if namespace:
        cands = [r for r in cands if r.ns == namespace or r.ns is None]
    if len(cands) == 1:
        return cands[0]
    if len(cands) > 1:
        where = ", ".join(f"{r.ns or '(no namespace)'} in {r.file.display}:{r.line('kind')}" for r in cands[:6])
        raise UserError(f"{shorten(kind)}/{shorten(name)} is defined {len(cands)} times ({where}). Pass namespace to pick one.")
    same_kind = sorted({r.name for r in rs.resources if r.kind.lower() == k})
    if same_kind:
        raise UserError(f"No {shorten(kind)} named {shorten(name)!r} in these files. {kind} objects found: {', '.join(same_kind[:20])}.")
    kinds = sorted({r.kind for r in rs.resources})
    raise UserError(f"No object of kind {shorten(kind)!r} in these files. Kinds present: {', '.join(kinds[:30]) or 'none'}.")


def _posture(pv: PodView, c: Container) -> str:
    sc = as_dict(c.data.get("securityContext"))
    psc = as_dict(pv.spec.get("securityContext"))

    def eff(key: str) -> object:
        return sc.get(key, psc.get(key))

    bits: list[str] = []
    uid, nonroot = eff("runAsUser"), eff("runAsNonRoot")
    if uid == 0 and not isinstance(uid, bool):
        bits.append("runs as ROOT (uid 0)")
    elif nonroot is True or (isinstance(uid, int) and not isinstance(uid, bool) and uid > 0):
        bits.append("non-root enforced")
    elif nonroot is False:
        bits.append("root explicitly allowed")
    else:
        bits.append("user not constrained (root if the image says so)")
    if sc.get("privileged") is True:
        bits.append("PRIVILEGED")
    bits.append("no privilege escalation" if sc.get("allowPrivilegeEscalation") is False else "privilege escalation allowed")
    bits.append("read-only root filesystem" if sc.get("readOnlyRootFilesystem") is True else "writable root filesystem")
    drop = [str(x).upper() for x in as_list(as_dict(sc.get("capabilities")).get("drop"))]
    add = [str(x).upper() for x in as_list(as_dict(sc.get("capabilities")).get("add"))]
    bits.append("all capabilities dropped" if "ALL" in drop else "default capabilities kept")
    if add:
        bits.append("adds " + ", ".join(add))
    res = as_dict(c.data.get("resources"))
    req, lim = as_dict(res.get("requests")), as_dict(res.get("limits"))
    bits.append("requests " + ("set" if req else "unset") + ", limits " + ("set" if lim else "unset"))
    return "; ".join(bits)


def _workload(res: Resource, pv: PodView, rs: ResourceSet) -> list[str]:
    out: list[str] = []
    cs = pv.containers(init=False)
    inits = [c for c in pv.containers() if c.init]
    spec = as_dict(res.get("spec"))
    what = {
        "Deployment": f"keeps {spec.get('replicas', 1)} replica(s) of a pod running and rolls out changes gradually",
        "StatefulSet": f"keeps {spec.get('replicas', 1)} ordered replica(s) with stable names and storage",
        "DaemonSet": "runs one pod on every (matching) node",
        "ReplicaSet": f"keeps {spec.get('replicas', 1)} identical pod(s) running",
        "Job": "runs a pod to completion once" + (f" ({spec.get('completions')} completions)" if spec.get("completions") else ""),
        "CronJob": f"runs a Job on the schedule '{spec.get('schedule')}'" if isinstance(spec.get("schedule"), str) else "runs a Job on a schedule",
        "Pod": "is a single pod, not managed by any controller",
        "ReplicationController": "keeps pods running (legacy controller)",
    }.get(res.kind, "runs pods")
    out.append(f"What it does: {res.label} {what}.")
    for c in cs:
        img = c.data.get("image")
        ports = [f"{as_dict(p).get('containerPort')}/{as_dict(p).get('protocol', 'TCP')}" for p in as_list(c.data.get("ports")) if isinstance(p, dict)]
        probes = [p for p in ("livenessProbe", "readinessProbe", "startupProbe") if p in c.data]
        line = f"  - container '{c.name}': image {img if isinstance(img, str) else '?'}"
        if isinstance(img, str):
            _, tag, digest = parse_image(img)
            line += " (digest-pinned)" if digest else f" (tag {tag})" if tag else " (no tag = latest)"
        if ports:
            line += f", listens on {', '.join(ports)}"
        line += f", probes: {', '.join(p.replace('Probe', '') for p in probes) or 'none'}"
        out.append(line)
    if inits:
        out.append("  - init containers: " + ", ".join(c.name for c in inits))
    out += ["", "Security posture:"]
    for c in pv.containers():
        out.append(f"  - {c.name}: {_posture(pv, c)}")
    host = [k for k in ("hostNetwork", "hostPID", "hostIPC") if pv.spec.get(k) is True]
    hp = [as_dict(as_dict(v).get("hostPath")).get("path") for v in as_list(pv.spec.get("volumes")) if isinstance(as_dict(as_dict(v).get("hostPath")).get("path"), str)]
    out.append("  - host access: " + (", ".join(host + [f"hostPath {p}" for p in hp]) if host or hp else "none"))
    out.append(f"  - service account: {pv.spec.get('serviceAccountName', 'default')}, token auto-mount "
               + ("on" if pv.spec.get("automountServiceAccountToken") is True else "off" if pv.spec.get("automountServiceAccountToken") is False else "default (on)"))
    seccomp = dig(pv.spec, "securityContext", "seccompProfile", "type")
    out.append(f"  - seccomp: {seccomp or 'not set'}")

    out += ["", "Depends on:"]
    deps: Counter[tuple[str, str]] = Counter()
    lines: list[str] = []
    for ref in pod_refs(pv):
        target = rs.find(ref.kind, ref.name, res.ns)
        status = f"defined in {target.file.display}:{target.line('kind')}" if target else "NOT defined in these files"
        key = (ref.kind, ref.name)
        if key in deps:
            continue
        deps[key] += 1
        lines.append(f"  - {ref.kind} '{ref.name}' ({status})")
    out += lines or ["  - no ConfigMaps, Secrets, PVCs or custom ServiceAccounts referenced"]
    plain, from_secret = 0, []
    for c in cs:
        for e in as_list(c.data.get("env")):
            e = as_dict(e)
            if "value" in e:
                plain += 1
            elif as_dict(e.get("valueFrom")).get("secretKeyRef"):
                from_secret.append(str(e.get("name")))
    out.append(f"  - environment: {plain} literal variable(s) (values not shown)"
               + (f"; from Secrets: {', '.join(from_secret)}" if from_secret else ""))

    labels = pv.template_labels
    out += ["", "Reached through / managed by:"]
    reach: list[str] = []
    for svc in rs.of_kind("Service"):
        if ns_match(svc.ns, res.ns) and _svc_matches(svc, labels):
            reach.append(f"Service '{svc.name}' ({svc.get('spec', 'type') or 'ClusterIP'})")
            for ing in rs.of_kind("Ingress"):
                if ns_match(ing.ns, res.ns) and svc.name in _ingress_services(ing):
                    reach.append(f"Ingress '{ing.name}' via Service '{svc.name}'")
    for hpa in rs.of_kind("HorizontalPodAutoscaler"):
        scale_ref = as_dict(hpa.get("spec", "scaleTargetRef"))
        if scale_ref.get("kind") == res.kind and scale_ref.get("name") == res.name:
            reach.append(f"HorizontalPodAutoscaler '{hpa.name}' ({hpa.get('spec', 'minReplicas')}-{hpa.get('spec', 'maxReplicas')} replicas)")
    for pdb in rs.of_kind("PodDisruptionBudget"):
        if ns_match(pdb.ns, res.ns) and label_selector_matches(pdb.get("spec", "selector"), labels):
            reach.append(f"PodDisruptionBudget '{pdb.name}'")
    for np in rs.of_kind("NetworkPolicy"):
        if ns_match(np.ns, res.ns) and label_selector_matches(np.get("spec", "podSelector"), labels):
            reach.append(f"NetworkPolicy '{np.name}'")
    out += [f"  - {r}" for r in reach] or ["  - nothing in these files selects it"]
    return out


def _svc_matches(svc: Resource, labels: dict[str, str]) -> bool:
    return map_selector_matches(svc.get("spec", "selector"), labels)


def _ingress_services(ing: Resource) -> set[str]:
    return {name for _, name, _ in _ingress_backends(ing)}


def _service(res: Resource, rs: ResourceSet) -> list[str]:
    spec = as_dict(res.get("spec"))
    typ = spec.get("type", "ClusterIP")
    ports = [f"{as_dict(p).get('port')} -> {as_dict(p).get('targetPort', as_dict(p).get('port'))}" for p in as_list(spec.get("ports"))]
    out = [f"What it does: gives a stable address to a set of pods. Type {typ}; ports {', '.join(ports) or 'none'}."]
    sel = spec.get("selector")
    if typ == "ExternalName":
        out.append(f"It is a DNS alias to {spec.get('externalName')}.")
    elif isinstance(sel, dict) and sel:
        pods = selected_pods(res, rs)
        out.append(f"It selects pods labelled {dict(sel)}: " + (", ".join(pv.res.label for pv in pods) if pods else "no workload in these files matches"))
    else:
        out.append("It has no selector: endpoints must be managed by hand.")
    exposure = {"LoadBalancer": "Exposure: provisions a cloud load balancer reachable from outside the cluster.",
                "NodePort": "Exposure: opens a port on every node.",
                "ClusterIP": "Exposure: reachable only inside the cluster."}.get(str(typ))
    if exposure:
        out.append(exposure)
    used_by = [i.label for i in rs.of_kind("Ingress") if res.name in _ingress_services(i) and ns_match(i.ns, res.ns)]
    out.append("Routed to by Ingress: " + (", ".join(used_by) if used_by else "none in these files"))
    return out


def _ingress(res: Resource, rs: ResourceSet) -> list[str]:
    out = ["What it does: routes external HTTP(S) traffic to Services."]
    for r in as_list(res.get("spec", "rules")):
        host = as_dict(r).get("host", "any host")
        for p in as_list(as_dict(as_dict(r).get("http")).get("paths")):
            b = as_dict(as_dict(p).get("backend"))
            svc = as_dict(b.get("service"))
            out.append(f"  - {host}{as_dict(p).get('path', '/')} -> Service {svc.get('name', b.get('serviceName'))}")
    out.append("TLS: " + ("terminated for " + ", ".join(str(h) for t in as_list(res.get("spec", "tls")) for h in as_list(as_dict(t).get("hosts"))) if as_list(res.get("spec", "tls")) else "none (plain HTTP)"))
    return out


def _data_object(res: Resource, rs: ResourceSet) -> list[str]:
    keys: dict[str, int] = {}
    for section in ("data", "binaryData", "stringData"):
        for k, v in as_dict(res.get(section)).items():
            keys[str(k)] = len(v) if isinstance(v, str) else 0
    out = [f"What it does: stores {len(keys)} {'secret ' if res.kind == 'Secret' else 'configuration '}key(s) for pods to consume."]
    out.append("Keys (values never shown): " + (", ".join(f"{k} ({n} chars)" for k, n in list(keys.items())[:30]) or "none in these files"))
    users: list[str] = []
    for pv in rs.workloads():
        if not ns_match(pv.res.ns, res.ns):
            continue
        if any(ref.kind == res.kind and ref.name == res.name for ref in pod_refs(pv)):
            users.append(pv.res.label)
    out.append("Used by: " + (", ".join(sorted(set(users))) if users else "no workload in these files"))
    if res.kind == "Secret":
        out.append(f"Type: {res.get('type') or 'Opaque'}")
    return out


def _rbac(res: Resource, rs: ResourceSet) -> list[str]:
    out: list[str] = []
    if res.kind in ("Role", "ClusterRole"):
        scope = "the whole cluster" if res.kind == "ClusterRole" else f"namespace {res.ns or '(current)'}"
        out.append(f"What it does: lists permissions valid in {scope}; it grants nothing until a binding refers to it.")
        for r in as_list(res.get("rules")):
            r = as_dict(r)
            what = ", ".join(str(x) for x in as_list(r.get("resources")) or as_list(r.get("nonResourceURLs")))
            out.append(f"  - may {', '.join(str(v) for v in as_list(r.get('verbs')))} on {what}"
                       + (f" (API groups {', '.join(repr(g) for g in as_list(r.get('apiGroups')))})" if r.get("apiGroups") else ""))
        bound = [b for b in rs.of_kind("RoleBinding", "ClusterRoleBinding") if as_dict(b.get("roleRef")).get("name") == res.name]
        out.append("Bound by: " + (", ".join(b.label for b in bound) if bound else "no binding in these files"))
    else:
        ref = as_dict(res.get("roleRef"))
        subs = [f"{as_dict(s).get('kind')} {as_dict(s).get('name')}" for s in as_list(res.get("subjects"))]
        out.append(f"What it does: gives the permissions of {ref.get('kind')} '{ref.get('name')}' to {', '.join(subs) or 'nobody'}.")
    return out


def _service_account(res: Resource, rs: ResourceSet) -> list[str]:
    out = [f"What it does: an identity for pods. Token auto-mount: {res.get('automountServiceAccountToken', 'default (on)')}."]
    users = [pv.res.label for pv in rs.workloads() if pv.spec.get("serviceAccountName") == res.name and ns_match(pv.res.ns, res.ns)]
    out.append("Used by: " + (", ".join(users) if users else "no workload in these files"))
    binds = []
    for b in rs.of_kind("RoleBinding", "ClusterRoleBinding"):
        for s in as_list(b.get("subjects")):
            s = as_dict(s)
            if s.get("kind") == "ServiceAccount" and s.get("name") == res.name:
                binds.append(f"{b.label} -> {as_dict(b.get('roleRef')).get('name')}")
    out.append("Permissions via: " + (", ".join(binds) if binds else "no binding in these files"))
    return out


def explain(rs: ResourceSet, res: Resource, findings: list[Finding]) -> str:
    out = [f"{res.label}" + (f" in namespace {res.ns}" if res.ns else "") + f" ({res.api}), defined at {res.file.display}:{res.line('kind')}", ""]
    pv = pod_view(res)
    if pv is not None:
        out += _workload(res, pv, rs)
    elif res.kind == "Service":
        out += _service(res, rs)
    elif res.kind == "Ingress":
        out += _ingress(res, rs)
    elif res.kind in ("ConfigMap", "Secret"):
        out += _data_object(res, rs)
    elif res.kind in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"):
        out += _rbac(res, rs)
    elif res.kind == "ServiceAccount":
        out += _service_account(res, rs)
    elif res.kind == "HorizontalPodAutoscaler":
        ref = as_dict(res.get("spec", "scaleTargetRef"))
        out.append(f"What it does: scales {ref.get('kind')} '{ref.get('name')}' between {dig(res.obj, 'spec', 'minReplicas')} and {dig(res.obj, 'spec', 'maxReplicas')} replicas based on metrics.")
    elif res.kind == "PodDisruptionBudget":
        out.append(f"What it does: limits voluntary evictions (node drains) of the pods it selects: minAvailable={dig(res.obj, 'spec', 'minAvailable')}, maxUnavailable={dig(res.obj, 'spec', 'maxUnavailable')}.")
    elif res.kind == "NetworkPolicy":
        types = as_list(res.get("spec", "policyTypes")) or ["Ingress"]
        out.append(f"What it does: restricts {', '.join(str(t) for t in types)} traffic for pods matching {dict(as_dict(dig(res.obj, 'spec', 'podSelector')).get('matchLabels') or {}) or 'every pod in the namespace'}.")
    elif res.kind == "PersistentVolumeClaim":
        out.append(f"What it does: requests {dig(res.obj, 'spec', 'resources', 'requests', 'storage')} of storage (class {dig(res.obj, 'spec', 'storageClassName') or 'default'}, modes {dig(res.obj, 'spec', 'accessModes')}).")
    elif res.kind == "Namespace":
        out.append("What it does: a boundary for names, quotas and policies.")
    else:
        spec = res.get("spec")
        out.append(f"No detailed explanation exists for kind {res.kind}. Top-level fields: {', '.join(k for k in res.obj if k not in ('apiVersion', 'kind')) or 'none'}"
                   + (f"; spec fields: {', '.join(str(k) for k in spec)}" if isinstance(spec, dict) else "") + ".")
    c = Counter(f.severity for f in findings)
    out += ["", f"Lint findings for this object: {len(findings)} ({c['error']} error, {c['warning']} warning, {c['info']} info)."]
    for f in findings[:25]:
        out.append(f"  [{f.rule}] {f.severity} line {f.line}: {f.message}")
    if len(findings) > 25:
        out.append(f"  ... +{len(findings) - 25} more")
    return clip("\n".join(out))
