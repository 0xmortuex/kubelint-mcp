"""k8s_overview: what is in these files, at a glance."""

from __future__ import annotations

from collections import Counter

from .model import Resource, ResourceSet, NAMESPACED, as_dict, as_list, dig
from .report import clip
from .rules_refs import selected_pods

MAX_LISTED = 60


def _port_text(p: dict[str, object]) -> str:
    n = p.get("containerPort")
    return f"{n}/{p.get('protocol', 'TCP')}" + (f" ({p['name']})" if p.get("name") else "")


def overview(rs: ResourceSet, label: str) -> str:
    out: list[str] = []
    out.append(f"{label}: {len(rs.resources)} object(s) in {len(rs.files)} file(s).")
    if rs.load_hits:
        out.append(f"{len(rs.load_hits)} YAML/structure problem(s) (run lint_manifests for details).")
    if not rs.resources:
        out.append(rs.lint_note or "No Kubernetes objects found.")
        return "\n".join(out)

    kinds = Counter(r.kind for r in rs.resources)
    out += ["", "By kind: " + ", ".join(f"{k} x{n}" for k, n in sorted(kinds.items()))]

    by_ns: dict[str, list[Resource]] = {}
    for r in rs.resources:
        by_ns.setdefault(r.ns or ("(cluster-scoped)" if r.kind not in NAMESPACED else "(no namespace set)"), []).append(r)
    out += ["", "By namespace:"]
    for ns in sorted(by_ns):
        items = by_ns[ns]
        shown = ", ".join(r.label for r in items[:MAX_LISTED])
        more = f", ... +{len(items) - MAX_LISTED} more" if len(items) > MAX_LISTED else ""
        out.append(f"  {ns} ({len(items)}): {shown}{more}")

    images: Counter[str] = Counter()
    workload_lines: list[str] = []
    for pv in rs.workloads():
        parts: list[str] = []
        for c in pv.containers():
            img = c.data.get("image")
            if isinstance(img, str):
                images[img] += 1
            ports = [_port_text(as_dict(p)) for p in as_list(c.data.get("ports")) if isinstance(p, dict)]
            parts.append(f"{c.name} [{img if isinstance(img, str) else '?'}]" + (f" ports {', '.join(ports)}" if ports else ""))
        reps = pv.res.get("spec", "replicas")
        head = f"  {pv.res.label} (ns {pv.res.ns or '-'})" + (f" replicas={reps}" if reps is not None and pv.res.kind in ("Deployment", "StatefulSet", "ReplicaSet") else "")
        workload_lines.append(head + ": " + "; ".join(parts))
    if workload_lines:
        out += ["", "Workloads:"] + workload_lines[:MAX_LISTED]
        if len(workload_lines) > MAX_LISTED:
            out.append(f"  ... +{len(workload_lines) - MAX_LISTED} more")
    if images:
        out += ["", "Images used:"] + [f"  {img}  (x{n})" for img, n in sorted(images.items())[:MAX_LISTED]]

    svc_lines: list[str] = []
    for s in rs.of_kind("Service"):
        typ = s.get("spec", "type") or "ClusterIP"
        ports = [f"{p.get('port')}->{p.get('targetPort', p.get('port'))}/{p.get('protocol', 'TCP')}" for p in map(as_dict, as_list(s.get("spec", "ports")))]
        targets = [pv.res.label for pv in selected_pods(s, rs)]
        extra = ""
        if typ == "NodePort":
            nps = [str(as_dict(p).get("nodePort")) for p in as_list(s.get("spec", "ports")) if as_dict(p).get("nodePort")]
            extra = f" nodePorts {', '.join(nps)}" if nps else ""
        svc_lines.append(f"  {s.label} (ns {s.ns or '-'}) {typ} ports {', '.join(ports) or '-'}{extra} -> "
                         + (", ".join(targets) if targets else "no workload in these files"))
    if svc_lines:
        out += ["", "Services:"] + svc_lines[:MAX_LISTED]

    ing_lines: list[str] = []
    for ing in rs.of_kind("Ingress"):
        tls = "TLS" if as_list(ing.get("spec", "tls")) else "no TLS"
        routes: list[str] = []
        for r in as_list(ing.get("spec", "rules")):
            host = as_dict(r).get("host", "*")
            for p in as_list(as_dict(as_dict(r).get("http")).get("paths")):
                b = as_dict(as_dict(p).get("backend"))
                svc = as_dict(b.get("service"))
                name = svc.get("name", b.get("serviceName", "?"))
                port = as_dict(svc.get("port")).get("number", as_dict(svc.get("port")).get("name", b.get("servicePort", "?")))
                routes.append(f"{host}{as_dict(p).get('path', '/')} -> {name}:{port}")
        ing_lines.append(f"  {ing.label} ({tls}): " + ("; ".join(routes) if routes else "no rules"))
    if ing_lines:
        out += ["", "Ingresses:"] + ing_lines[:MAX_LISTED]

    exposed = [pv for pv in rs.workloads() if dig(pv.spec, "hostNetwork") is True]
    if exposed:
        out += ["", "Host-network workloads: " + ", ".join(pv.res.label for pv in exposed)]
    note = rs.lint_note
    if note:
        out += ["", note]
    return clip("\n".join(out))

