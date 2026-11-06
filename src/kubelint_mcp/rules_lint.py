"""K8S1xxx: manifest hygiene and security rules (one resource at a time, plus a few set-wide checks)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from . import deprecations
from .findings import Hit
from .model import (
    LONG_RUNNING,
    NAMESPACED,
    Container,
    PodView,
    Resource,
    ResourceSet,
    as_dict,
    as_list,
    dig,
    label_selector_matches,
    ns_match,
    pod_view,
)
from .registry import rule
from .secrets import is_placeholder, is_secret_name, redacted, secret_value_kind
from .yamlpos import Path

Hits = Iterator[Hit]

DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH", "BPF", "SYS_BOOT", "MKNOD"}
SENSITIVE_HOST_PREFIXES = ("/etc", "/proc", "/sys", "/var/lib/kubelet", "/root", "/boot", "/dev", "/var/run", "/run", "/var/lib/docker")
RUNTIME_SOCKETS = ("docker.sock", "containerd.sock", "crio.sock", "podman.sock", "cri-dockerd.sock")


def parse_image(image: str) -> tuple[str, str | None, str | None]:
    """(name, tag, digest) for an image reference; registry ports are not mistaken for tags."""
    ref, _, digest = image.partition("@")
    last = ref.rsplit("/", 1)[-1]
    tag = None
    if ":" in last:
        tag = last.split(":", 1)[1]
        ref = ref[: len(ref) - len(tag) - 1]
    return ref, tag or None, digest or None


def _templated(image: str) -> bool:
    return any(t in image for t in ("{{", "$(", "${"))


def _where(c: Container, key: str) -> Path:
    return c.path + (key,) if key in c.data else c.path


def _sc(c: Container) -> dict[str, Any]:
    return as_dict(c.data.get("securityContext"))


def _eff(pv: PodView, c: Container, key: str) -> tuple[Any, Path]:
    """Effective securityContext field: the container's own value wins over the pod's."""
    csc = _sc(c)
    if key in csc:
        return csc[key], c.path + ("securityContext", key)
    psc = as_dict(pv.spec.get("securityContext"))
    if key in psc:
        return psc[key], pv.path + ("securityContext", key)
    return None, c.path


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


# ------------------------------------------------------------------ resources and images


@rule("K8S1001", "warning", "container has no resource requests")
def no_requests(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        r = as_dict(c.data.get("resources"))
        req, lim = as_dict(r.get("requests")), as_dict(r.get("limits"))
        missing = [k for k in ("cpu", "memory") if k not in req and k not in lim]
        if missing:
            yield res.hit(
                _where(c, "resources"),
                f"container '{c.name}' sets no {' or '.join(missing)} request, so the scheduler cannot place it sensibly "
                "and it lands in the BestEffort/Burstable QoS class",
                f"Under container '{c.name}' add: resources: {{requests: {{cpu: 100m, memory: 128Mi}}}} (size from real usage).",
            )


@rule("K8S1002", "warning", "container has no memory limit")
def no_memory_limit(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        lim = as_dict(as_dict(c.data.get("resources")).get("limits"))
        if "memory" not in lim:
            yield res.hit(
                _where(c, "resources"),
                f"container '{c.name}' has no memory limit; a leak can take the whole node down (CPU limits are deliberately not required)",
                f"Under container '{c.name}' add: resources: {{limits: {{memory: 256Mi}}}}.",
            )


@rule("K8S1003", "warning", "image is untagged or uses :latest")
def image_latest(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        image = c.data.get("image")
        if not isinstance(image, str) or _templated(image):
            continue
        _, tag, digest = parse_image(image)
        if digest:
            continue
        if tag is None:
            yield res.hit(c.path + ("image",), f"image '{image}' has no tag, which means :latest",
                          f"Pin a version: image: {image}:<version> (better, add @sha256:<digest>).")
        elif tag == "latest":
            yield res.hit(c.path + ("image",), f"image '{image}' uses the mutable :latest tag",
                          "Pin a version tag (better, a digest) so rollouts and rollbacks are reproducible.")


@rule("K8S1004", "info", "image is not pinned by digest")
def image_no_digest(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        image = c.data.get("image")
        if not isinstance(image, str) or _templated(image):
            continue
        _, tag, digest = parse_image(image)
        if not digest and tag not in (None, "latest"):
            yield res.hit(c.path + ("image",), f"image '{image}' is pinned by tag only; tags can be re-pushed",
                          f"Append the digest: image: {image}@sha256:<digest> (`docker buildx imagetools inspect {image}`).")


# ------------------------------------------------------------------ container security context


@rule("K8S1005", "error", "privileged container")
def privileged(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        if _sc(c).get("privileged") is True:
            yield res.hit(c.path + ("securityContext", "privileged"),
                          f"container '{c.name}' is privileged: it has every capability and full access to host devices",
                          "Remove privileged: true, or grant only the specific capabilities needed (capabilities.add).")


@rule("K8S1006", "warning", "allowPrivilegeEscalation is not false")
def priv_escalation(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        val = _sc(c).get("allowPrivilegeEscalation")
        if val is True:
            yield res.hit(c.path + ("securityContext", "allowPrivilegeEscalation"),
                          f"container '{c.name}' explicitly allows privilege escalation (setuid binaries can gain more rights)",
                          "Set securityContext.allowPrivilegeEscalation: false.", "error")
        elif val is not False and _sc(c).get("privileged") is not True:
            yield res.hit(_where(c, "securityContext"),
                          f"container '{c.name}' does not set allowPrivilegeEscalation: false (the default is true)",
                          "Add securityContext.allowPrivilegeEscalation: false.")


@rule("K8S1007", "error", "container runs as root")
def runs_as_root(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        uid, upath = _eff(pv, c, "runAsUser")
        nonroot, npath = _eff(pv, c, "runAsNonRoot")
        if uid == 0 and _is_int(uid):
            yield res.hit(upath, f"container '{c.name}' runs as UID 0 (root)", "Set runAsUser to a non-zero UID such as 10001 and runAsNonRoot: true.")
        elif nonroot is False:
            yield res.hit(npath, f"container '{c.name}' sets runAsNonRoot: false, so root is allowed",
                          "Set runAsNonRoot: true and a non-zero runAsUser.")


@rule("K8S1008", "warning", "runAsNonRoot is not enforced")
def not_nonroot(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        uid, _ = _eff(pv, c, "runAsUser")
        nonroot, _ = _eff(pv, c, "runAsNonRoot")
        if nonroot is False or (_is_int(uid) and uid == 0):
            continue  # K8S1007 covers it
        if nonroot is True or (_is_int(uid) and uid > 0):
            continue
        yield res.hit(_where(c, "securityContext"),
                      f"container '{c.name}' does not require a non-root user; an image that defaults to root will run as root",
                      "Add securityContext.runAsNonRoot: true (container or pod level) and runAsUser: 10001.")


@rule("K8S1009", "warning", "root filesystem is writable")
def writable_rootfs(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        if _sc(c).get("readOnlyRootFilesystem") is not True:
            yield res.hit(_where(c, "securityContext"),
                          f"container '{c.name}' has a writable root filesystem, so an attacker can drop tools and persist changes",
                          "Add securityContext.readOnlyRootFilesystem: true and mount an emptyDir at the paths that need writes (/tmp).")


@rule("K8S1010", "warning", "capabilities are not dropped")
def caps_not_dropped(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        drop = [str(x).upper() for x in as_list(as_dict(_sc(c).get("capabilities")).get("drop"))]
        if "ALL" not in drop:
            yield res.hit(_where(c, "securityContext"),
                          f"container '{c.name}' keeps the default Linux capabilities; it should drop all and add back only what it needs",
                          "Add securityContext.capabilities: {drop: [ALL]} (and add: [NET_BIND_SERVICE] if it binds a port below 1024).")


@rule("K8S1011", "error", "dangerous capability added")
def caps_added(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        caps = as_dict(_sc(c).get("capabilities"))
        for i, cap in enumerate(as_list(caps.get("add"))):
            name = str(cap).upper().removeprefix("CAP_")
            if name == "NET_BIND_SERVICE":
                continue
            sev = "error" if name in DANGEROUS_CAPS else "warning"
            yield res.hit(c.path + ("securityContext", "capabilities", "add", i),
                          f"container '{c.name}' adds capability {name}, which the restricted Pod Security profile does not allow",
                          "Remove it, or isolate the workload and document why it needs it.", sev)


# ------------------------------------------------------------------ pod-level host access


@rule("K8S1012", "error", "hostNetwork is enabled")
def host_network(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is not None and pv.spec.get("hostNetwork") is True:
        yield res.hit(pv.path + ("hostNetwork",), "pod shares the node's network namespace (it can reach node-local services and sniff traffic)",
                      "Remove hostNetwork: true; expose the port through a Service instead.")


@rule("K8S1013", "error", "hostPID or hostIPC is enabled")
def host_pid_ipc(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for key in ("hostPID", "hostIPC"):
        if pv.spec.get(key) is True:
            yield res.hit(pv.path + (key,), f"pod sets {key}: true and can see or signal host processes/shared memory",
                          f"Remove {key}: true.")


def _host_volumes(pv: PodView) -> Iterator[tuple[int, str, str]]:
    for i, v in enumerate(as_list(pv.spec.get("volumes"))):
        hp = as_dict(as_dict(v).get("hostPath"))
        path = hp.get("path")
        if isinstance(path, str):
            yield i, str(as_dict(v).get("name", "")), path


@rule("K8S1014", "warning", "hostPath volume")
def host_path(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for i, vname, path in _host_volumes(pv):
        norm = path.rstrip("/") or "/"
        if norm.endswith(RUNTIME_SOCKETS):
            continue  # K8S1015
        sensitive = norm == "/" or norm.startswith(SENSITIVE_HOST_PREFIXES)
        yield res.hit(pv.path + ("volumes", i, "hostPath"),
                      f"volume '{vname}' mounts the host path {path}" + (", a sensitive location" if sensitive else ""),
                      "Use an emptyDir, a PersistentVolumeClaim or a ConfigMap/Secret volume; if a host path is unavoidable make it readOnly and as narrow as possible.",
                      "error" if sensitive else "warning")


@rule("K8S1015", "error", "container runtime socket mounted")
def runtime_socket(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for i, vname, path in _host_volumes(pv):
        if (path.rstrip("/")).endswith(RUNTIME_SOCKETS):
            yield res.hit(pv.path + ("volumes", i, "hostPath"),
                          f"volume '{vname}' mounts {path}: whoever controls this pod controls every container on the node (root on the host)",
                          "Do not mount the runtime socket. Build images with kaniko/buildah in-cluster, or use a dedicated, isolated node pool.")


# ------------------------------------------------------------------ probes, replicas, availability


def _long_running(pv: PodView) -> bool:
    if pv.res.kind not in LONG_RUNNING:
        return False
    return not (pv.res.kind == "Pod" and pv.spec.get("restartPolicy") in ("Never", "OnFailure"))


@rule("K8S1016", "warning", "no livenessProbe")
def no_liveness(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None or not _long_running(pv):
        return
    for c in pv.containers(init=False):
        if "livenessProbe" not in c.data:
            yield res.hit(c.path, f"container '{c.name}' has no livenessProbe, so a hung process is never restarted",
                          "Add livenessProbe (httpGet /healthz, or exec/tcpSocket) with initialDelaySeconds/periodSeconds.")


@rule("K8S1017", "warning", "no readinessProbe")
def no_readiness(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None or not _long_running(pv):
        return
    for c in pv.containers(init=False):
        if "readinessProbe" not in c.data:
            yield res.hit(c.path, f"container '{c.name}' has no readinessProbe, so traffic and rollouts do not wait for it to be ready",
                          "Add readinessProbe (httpGet on a ready endpoint, or tcpSocket) before relying on rolling updates.")


@rule("K8S1018", "info", "single replica")
def single_replica(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind in ("Deployment", "StatefulSet") and _is_int(res.get("spec", "replicas")) and res.get("spec", "replicas") == 1:
        yield res.hit(("spec", "replicas"), f"{res.label} runs one replica: any restart or node drain is an outage",
                      "Use replicas: 2 or more (with anti-affinity/topology spread) if availability matters.")


@rule("K8S1019", "info", "replicated workload has no PodDisruptionBudget")
def no_pdb(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind not in ("Deployment", "StatefulSet"):
        return
    n = res.get("spec", "replicas")
    pv = pod_view(res)
    if pv is None or not _is_int(n) or n < 2:
        return
    labels = pv.template_labels
    for pdb in rs.of_kind("PodDisruptionBudget"):
        if ns_match(pdb.ns, res.ns) and label_selector_matches(pdb.get("spec", "selector"), labels):
            return
    yield res.hit(("spec", "replicas"), f"{res.label} has {n} replicas but no PodDisruptionBudget in these files selects it, so a node drain can evict all of them at once",
                  "Add a policy/v1 PodDisruptionBudget with spec.minAvailable (or maxUnavailable) and the same selector labels.")


# ------------------------------------------------------------------ namespaces


@rule("K8S1020", "warning", "default namespace")
def default_ns(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind not in NAMESPACED:
        return
    ns = res.get("metadata", "namespace")
    if ns == "default":
        yield res.hit(("metadata", "namespace"), f"{res.label} is in the 'default' namespace, which has no isolation or per-team policy",
                      "Deploy into a dedicated namespace (metadata.namespace: <app>) with its own quotas and NetworkPolicies.")
    elif ns is None:
        yield res.hit(("metadata", "name"), f"{res.label} has no metadata.namespace, so it lands in whatever namespace the current kubectl context uses (often 'default')",
                      "Set metadata.namespace explicitly (or always pass -n and use a Kustomize/Helm namespace).", "info")


@rule("K8S1038", "info", "namespace has no Pod Security Admission label")
def namespace_psa(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "Namespace":
        return
    labels = as_dict(res.get("metadata", "labels"))
    if "pod-security.kubernetes.io/enforce" not in labels:
        yield res.hit(("metadata", "name"), f"Namespace '{res.name}' does not set pod-security.kubernetes.io/enforce, so no Pod Security Standard is enforced",
                      "Add the label pod-security.kubernetes.io/enforce: restricted (or baseline).")


# ------------------------------------------------------------------ secrets


@rule("K8S1021", "error", "secret as a plain env value")
def env_secrets(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        for i, e in enumerate(as_list(c.data.get("env"))):
            e = as_dict(e)
            name, value = e.get("name"), e.get("value")
            if not isinstance(name, str) or not isinstance(value, str) or is_placeholder(value):
                continue
            kind = secret_value_kind(value)
            if is_secret_name(name) or kind:
                why = f" (looks like a {kind})" if kind else ""
                yield res.hit(c.path + ("env", i),
                              f"env var {redacted(name, value)} is a literal in the manifest{why}",
                              f"Move it to a Secret and reference it: env: [{{name: {name}, valueFrom: {{secretKeyRef: {{name: <secret>, key: <key>}}}}}}]. Rotate the value, it is in version control.")


@rule("K8S1022", "warning", "secret-looking data in a ConfigMap")
def configmap_secrets(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "ConfigMap":
        return
    for key, value in as_dict(res.get("data")).items():
        if not isinstance(value, str) or is_placeholder(value):
            continue
        kind = secret_value_kind(value)
        by_name = "." not in str(key) and is_secret_name(str(key))
        if by_name or kind:
            why = f" (looks like a {kind})" if kind else ""
            yield res.hit(("data", str(key)), f"ConfigMap key {redacted(str(key), value)} looks like a secret{why}; ConfigMaps are not encrypted or access-restricted like Secrets",
                          "Move it into a Secret (or an external secret manager) and mount/reference that instead.")


@rule("K8S1023", "warning", "Secret with inline data in a manifest")
def inline_secret(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "Secret":
        return
    entries: list[str] = []
    for section in ("data", "stringData"):
        for key, value in as_dict(res.get(section)).items():
            if isinstance(value, str) and value and not is_placeholder(value):
                entries.append(redacted(str(key), value))
    if entries:
        shown = "; ".join(entries[:8]) + (f"; and {len(entries) - 8} more" if len(entries) > 8 else "")
        yield res.hit(("data",) if res.get("data") else ("stringData",),
                      f"Secret '{res.name}' carries its values in the manifest (base64 is encoding, not encryption): {shown}",
                      "Keep values out of git: use Sealed Secrets, SOPS, External Secrets or `kubectl create secret` from CI, and commit only references.")


# ------------------------------------------------------------------ service account, seccomp, pull policy


@rule("K8S1024", "info", "service account token is auto-mounted")
def automount(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    val = pv.spec.get("automountServiceAccountToken")
    if val is True:
        yield res.hit(pv.path + ("automountServiceAccountToken",), "pod explicitly mounts the service account token; a compromised container can call the Kubernetes API",
                      "Set automountServiceAccountToken: false unless the app talks to the API server.", "warning")
        return
    if val is False:
        return
    sa_name = pv.spec.get("serviceAccountName")
    sa = rs.find("ServiceAccount", sa_name if isinstance(sa_name, str) else "default", res.ns)
    if sa is not None and sa.get("automountServiceAccountToken") is False:
        return
    yield res.hit(pv.path, "the service account token is mounted into every container by default",
                  "Set spec.automountServiceAccountToken: false on the pod (or on its ServiceAccount) unless the app calls the API.")


@rule("K8S1025", "info", "no pod-level securityContext")
def no_pod_sc(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is not None and not as_dict(pv.spec.get("securityContext")):
        yield res.hit(pv.path, "pod has no securityContext (runAsNonRoot, fsGroup, seccompProfile apply to every container there)",
                      "Add spec.securityContext: {runAsNonRoot: true, runAsUser: 10001, fsGroup: 10001, seccompProfile: {type: RuntimeDefault}}.")


@rule("K8S1026", "warning", "no seccomp profile")
def seccomp(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    ok = ("RuntimeDefault", "Localhost")
    for i, c in enumerate(pv.containers()):
        t = dig(_sc(c), "seccompProfile", "type")
        if t == "Unconfined":
            yield res.hit(c.path + ("securityContext", "seccompProfile"), f"container '{c.name}' disables seccomp (Unconfined)",
                          "Use seccompProfile: {type: RuntimeDefault}.")
    pod_t = dig(pv.spec, "securityContext", "seccompProfile", "type")
    if pod_t in ok:
        return
    if pod_t == "Unconfined":
        yield res.hit(pv.path + ("securityContext", "seccompProfile"), "pod disables seccomp (Unconfined)", "Use seccompProfile: {type: RuntimeDefault}.")
        return
    cs = pv.containers()
    if cs and all(dig(_sc(c), "seccompProfile", "type") in ok for c in cs):
        return
    if any(dig(_sc(c), "seccompProfile", "type") == "Unconfined" for c in cs):
        return
    yield res.hit(pv.path + ("securityContext",) if "securityContext" in pv.spec else pv.path,
                  "no seccomp profile is set, so containers run with every syscall allowed (the default is Unconfined)",
                  "Add seccompProfile: {type: RuntimeDefault} under spec.securityContext.")


@rule("K8S1027", "warning", "imagePullPolicy problem")
def pull_policy(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        pol = c.data.get("imagePullPolicy")
        if pol is None:
            continue
        image = c.data.get("image")
        if pol not in ("Always", "IfNotPresent", "Never"):
            yield res.hit(c.path + ("imagePullPolicy",), f"imagePullPolicy '{pol}' is not valid (the API server rejects it)",
                          "Use Always, IfNotPresent or Never (the field is case-sensitive).", "error")
            continue
        if isinstance(image, str) and not _templated(image):
            _, tag, digest = parse_image(image)
            if pol != "Always" and not digest and tag in (None, "latest"):
                yield res.hit(c.path + ("imagePullPolicy",), f"imagePullPolicy: {pol} with a mutable tag means nodes keep serving a stale image",
                              "Pin the image version/digest, or use imagePullPolicy: Always.")
            elif pol == "Never":
                yield res.hit(c.path + ("imagePullPolicy",), "imagePullPolicy: Never only works when the image is already on every node",
                              "Use IfNotPresent unless images are preloaded on purpose.", "info")


# ------------------------------------------------------------------ services and ingress


_INTERNAL_LB = {
    "service.beta.kubernetes.io/aws-load-balancer-internal",
    "service.beta.kubernetes.io/azure-load-balancer-internal",
    "networking.gke.io/load-balancer-type",
    "cloud.google.com/load-balancer-type",
    "service.beta.kubernetes.io/aws-load-balancer-scheme",
    "service.beta.kubernetes.io/openstack-internal-load-balancer",
}


@rule("K8S1028", "warning", "Service of type LoadBalancer is exposed")
def load_balancer(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "Service" or res.get("spec", "type") != "LoadBalancer":
        return
    if as_list(res.get("spec", "loadBalancerSourceRanges")):
        return
    ann = as_dict(res.get("metadata", "annotations"))
    if any(k in ann and str(ann[k]).lower() in ("true", "internal") for k in _INTERNAL_LB):
        return
    yield res.hit(("spec", "type"), f"Service '{res.name}' creates a cloud load balancer reachable from the internet with no source restriction",
                  "Add spec.loadBalancerSourceRanges, use an internal-LB annotation for your cloud, or front it with an Ingress.")


@rule("K8S1029", "info", "Service of type NodePort is exposed")
def node_port(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind == "Service" and res.get("spec", "type") == "NodePort":
        yield res.hit(("spec", "type"), f"Service '{res.name}' opens a port on every node (30000-32767) outside any Ingress/LB policy",
                      "Prefer ClusterIP behind an Ingress; keep NodePort for development.")


@rule("K8S1030", "info", "namespace has no NetworkPolicy", scope="set")
def no_network_policy(rs: ResourceSet) -> Hits:
    policies = rs.of_kind("NetworkPolicy")
    reported: set[str | None] = set()
    for pv in rs.workloads():
        res = pv.res
        if res.ns in reported:
            continue
        if any(ns_match(p.ns, res.ns) for p in policies):
            continue
        reported.add(res.ns)
        where = f"namespace '{res.ns}'" if res.ns else "this namespace"
        yield res.hit((), f"{where} runs workloads but no NetworkPolicy in these files applies, so every pod can talk to every other pod",
                      "Add a default-deny NetworkPolicy (podSelector: {}, policyTypes: [Ingress, Egress]) and allow only the traffic you need.")


@rule("K8S1035", "warning", "Ingress without TLS")
def ingress_tls(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind == "Ingress" and not as_list(res.get("spec", "tls")):
        yield res.hit(("spec",), f"Ingress '{res.name}' has no spec.tls, so it serves plain HTTP",
                      "Add spec.tls: [{hosts: [<host>], secretName: <tls-secret>}] (cert-manager can issue the certificate).")


@rule("K8S1040", "warning", "Service uses externalIPs")
def external_ips(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind == "Service" and as_list(res.get("spec", "externalIPs")):
        yield res.hit(("spec", "externalIPs"), "spec.externalIPs lets anyone who can create a Service hijack that traffic (CVE-2020-8554)",
                      "Use a LoadBalancer Service or Ingress; block externalIPs with the DenyServiceExternalIPs admission controller.")


# ------------------------------------------------------------------ cronjobs, ports, pods


@rule("K8S1031", "warning", "CronJob concurrencyPolicy allows overlap")
def cron_concurrency(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "CronJob":
        return
    pol = res.get("spec", "concurrencyPolicy")
    if pol is None or pol == "Allow":
        yield res.hit(("spec", "concurrencyPolicy") if pol else ("spec",),
                      "concurrencyPolicy is Allow (the default): a slow run overlaps the next one and runs can pile up",
                      "Set spec.concurrencyPolicy: Forbid (skip while running) or Replace.")


@rule("K8S1032", "info", "CronJob history limits not set")
def cron_history(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind != "CronJob":
        return
    missing = [k for k in ("successfulJobsHistoryLimit", "failedJobsHistoryLimit") if k not in as_dict(res.get("spec"))]
    if missing:
        yield res.hit(("spec",), f"{' and '.join(missing)} not set; the defaults (3 and 1) are implicit",
                      "Set spec.successfulJobsHistoryLimit and spec.failedJobsHistoryLimit explicitly (for example 3 and 3).")


@rule("K8S1033", "error", "removed or deprecated apiVersion")
def deprecated_api(res: Resource, rs: ResourceSet) -> Hits:
    d = deprecations.lookup(res.api, res.kind)
    if d is None:
        return
    msg = deprecations.describe(d, res.kind)
    fix = f"Change apiVersion to {d.replacement}."
    if d.note:
        fix += f" {d.note}"
    yield res.hit(("apiVersion",), msg + f". Replacement: {d.replacement}.", fix, "error" if d.removed else "warning")


@rule("K8S1034", "warning", "hostPort in use")
def host_port(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    for c in pv.containers():
        for i, p in enumerate(as_list(c.data.get("ports"))):
            if isinstance(p, dict) and p.get("hostPort") is not None:
                yield res.hit(c.path + ("ports", i, "hostPort"),
                              f"container '{c.name}' binds hostPort {p.get('hostPort')}: it limits scheduling to one pod per node and bypasses Service policy",
                              "Remove hostPort and expose the port through a Service.")


@rule("K8S1036", "info", "bare Pod")
def bare_pod(res: Resource, rs: ResourceSet) -> Hits:
    if res.kind == "Pod" and not as_list(res.get("metadata", "ownerReferences")):
        yield res.hit(("kind",), "a bare Pod is not rescheduled if its node dies and has no rollout strategy",
                      "Wrap it in a Deployment (long-running) or Job (one-shot).")


@rule("K8S1037", "info", "workload uses the default service account")
def default_sa(res: Resource, rs: ResourceSet) -> Hits:
    pv = pod_view(res)
    if pv is None:
        return
    sa = pv.spec.get("serviceAccountName")
    if sa is None or sa == "default":
        yield res.hit(pv.path + ("serviceAccountName",) if "serviceAccountName" in pv.spec else pv.path,
                      "pod runs as the namespace's default ServiceAccount, which every other workload there shares",
                      "Create a dedicated ServiceAccount and set spec.serviceAccountName.")

