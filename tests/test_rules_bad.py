"""Bad manifests: each case mutates the clean base in one place and marks the line where the finding must
appear with `# !K8S1xxx`. The test asserts the rule id AND that exact line."""

from __future__ import annotations

import textwrap

import pytest

from conftest import DIGEST, POD_SC, RESOURCES, build_base, marked_lines

POD_SC_2 = textwrap.indent(textwrap.dedent(POD_SC), "  ")
IMG = f"registry.example.com/shop/web:1.4.2@{DIGEST}"
C_SC = "          securityContext:\n"
CONT = "        - name: app\n"
POD_SPEC = "    spec:\n      serviceAccountName: web\n"


def img(new: str) -> tuple[str, str]:
    return (f"          image: {IMG}\n", f"          image: {new}\n")


def after_image(extra: str) -> tuple[str, str]:
    return (f"          image: {IMG}\n", f"          image: {IMG}\n{extra}")


def after_sa(extra: str) -> tuple[str, str]:
    return ("      serviceAccountName: web\n", f"      serviceAccountName: web\n{extra}")


CRONJOB = """\
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
  namespace: shop
spec:%s
%s  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: web
          automountServiceAccountToken: false
          restartPolicy: Never
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: job
              image: registry.example.com/shop/job:2.0.0@sha256:%s
              resources:
                requests: {cpu: 50m, memory: 64Mi}
                limits: {memory: 128Mi}
              securityContext:
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                capabilities: {drop: [ALL]}
"""
GOOD_CRON_HEAD = "  concurrencyPolicy: Forbid\n  successfulJobsHistoryLimit: 3\n  failedJobsHistoryLimit: 3\n"
HEX = "b" * 64

# (rule, drop-docs, extra-docs, edits)
Case = tuple[str, tuple[str, ...], tuple[str, ...], tuple[tuple[str, str], ...]]
CASES: dict[str, Case] = {}


def case(name: str, rule: str, edits: tuple[tuple[str, str], ...] = (), drop: tuple[str, ...] = (), extra: tuple[str, ...] = ()) -> None:
    CASES[name] = (rule, drop, extra, edits)


# ---- resources and images
case("1001-no-resources", "K8S1001", ((RESOURCES, ""), (CONT, CONT.rstrip("\n") + " # !K8S1001\n")))
case("1001-no-memory-request", "K8S1001", (("              cpu: 100m\n", ""), ("          resources:\n", "          resources: # !K8S1001\n")))
case("1002-no-memory-limit", "K8S1002", (("            limits:\n              memory: 256Mi\n", ""), ("          resources:\n", "          resources: # !K8S1002\n")))
case("1003-latest-tag", "K8S1003", (img("registry.example.com/shop/web:latest # !K8S1003"),))
case("1003-untagged", "K8S1003", (img("registry.example.com/shop/web # !K8S1003"),))
case("1004-no-digest", "K8S1004", (img("registry.example.com/shop/web:1.4.2 # !K8S1004"),))
case("1003-registry-port-is-not-a-tag", "K8S1003", (img("localhost:5000/web # !K8S1003"),))
# ---- security context
case("1005-privileged", "K8S1005", (("            allowPrivilegeEscalation: false\n", "            allowPrivilegeEscalation: false\n            privileged: true # !K8S1005\n"),))
case("1006-escalation-true", "K8S1006", (("allowPrivilegeEscalation: false", "allowPrivilegeEscalation: true # !K8S1006"),))
case("1006-escalation-absent", "K8S1006", (("            allowPrivilegeEscalation: false\n", ""), (C_SC, C_SC.rstrip("\n") + " # !K8S1006\n")))
case("1007-run-as-root", "K8S1007", (("        runAsUser: 10001\n", "        runAsUser: 0 # !K8S1007\n"),))
case("1007-nonroot-false", "K8S1007", (("        runAsNonRoot: true\n", "        runAsNonRoot: false # !K8S1007\n"),))
case("1008-nonroot-not-enforced", "K8S1008", (("        runAsNonRoot: true\n        runAsUser: 10001\n", ""), (C_SC, C_SC.rstrip("\n") + " # !K8S1008\n")))
case("1009-writable-rootfs", "K8S1009", (("readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false"), (C_SC, C_SC.rstrip("\n") + " # !K8S1009\n")))
case("1010-caps-not-dropped", "K8S1010", (("drop: [ALL]", "drop: [NET_RAW]"), (C_SC, C_SC.rstrip("\n") + " # !K8S1010\n")))
case("1011-sys-admin", "K8S1011", (("              drop: [ALL]\n", "              drop: [ALL]\n              add: [SYS_ADMIN] # !K8S1011\n"),))
case("1011-net-admin-warning", "K8S1011", (("              drop: [ALL]\n", "              drop: [ALL]\n              add: [NET_ADMIN] # !K8S1011\n"),))
case("1026-no-seccomp", "K8S1026", (("        seccompProfile:\n          type: RuntimeDefault\n", ""), ("\n      securityContext:\n", "\n      securityContext: # !K8S1026\n")))
# ---- host access
case("1012-host-network", "K8S1012", (after_sa("      hostNetwork: true # !K8S1012\n"),))
case("1013-host-pid", "K8S1013", (after_sa("      hostPID: true # !K8S1013\n"),))
case("1013-host-ipc", "K8S1013", (after_sa("      hostIPC: true # !K8S1013\n"),))
case("1014-host-path", "K8S1014", (after_sa("      volumes:\n        - name: data\n          hostPath: # !K8S1014\n            path: /data\n"),))
case("1014-host-path-sensitive", "K8S1014", (after_sa("      volumes:\n        - name: etc\n          hostPath: # !K8S1014\n            path: /etc\n"),))
case("1015-docker-sock", "K8S1015", (after_sa("      volumes:\n        - name: sock\n          hostPath: # !K8S1015\n            path: /var/run/docker.sock\n"),))
case("1015-containerd-sock", "K8S1015", (after_sa("      volumes:\n        - name: sock\n          hostPath: # !K8S1015\n            path: /run/containerd/containerd.sock\n"),))
case("1034-host-port", "K8S1034", (("              containerPort: 8080\n", "              containerPort: 8080\n              hostPort: 8080 # !K8S1034\n"),))
# ---- probes and availability
case("1016-no-liveness", "K8S1016", (("          livenessProbe:\n            httpGet:\n              path: /healthz\n              port: http\n", ""), (CONT, CONT.rstrip("\n") + " # !K8S1016\n")))
case("1017-no-readiness", "K8S1017", (("          readinessProbe:\n            httpGet:\n              path: /ready\n              port: http\n", ""), (CONT, CONT.rstrip("\n") + " # !K8S1017\n")))
case("1018-single-replica", "K8S1018", (("  replicas: 2\n", "  replicas: 1 # !K8S1018\n"),))
case("1019-no-pdb", "K8S1019", (("  replicas: 2\n", "  replicas: 2 # !K8S1019\n"),), drop=("pdb",))
case("1019-pdb-selector-mismatch", "K8S1019", (("  replicas: 2\n", "  replicas: 2 # !K8S1019\n"), ("  minAvailable: 1\n  selector:\n    matchLabels:\n      app: web\n", "  minAvailable: 1\n  selector:\n    matchLabels:\n      app: other\n")))
case("1030-no-network-policy", "K8S1030", (("kind: Deployment\n", "kind: Deployment # !K8S1030\n"),), drop=("netpol",))
# ---- namespaces
case("1020-explicit-default", "K8S1020", (("  namespace: shop\n  labels:\n", "  namespace: default # !K8S1020\n  labels:\n"),))
case("1020-namespace-omitted", "K8S1020", (("  name: web\n  namespace: shop\n  labels:\n", "  name: web # !K8S1020\n  labels:\n"),))
case("1038-no-psa-label", "K8S1038", (("  name: shop\n  labels:\n    pod-security.kubernetes.io/enforce: restricted\n", "  name: shop # !K8S1038\n"),))
# ---- secrets
case("1021-env-password", "K8S1021", (after_image("          env:\n            - name: DB_PASSWORD # !K8S1021\n              value: hunter2-fake-value\n"),))
case("1021-env-token-camel", "K8S1021", (after_image("          env:\n            - name: githubToken # !K8S1021\n              value: abc123\n"),))
case("1021-env-aws-key-value", "K8S1021", (after_image("          env:\n            - name: CREDS # !K8S1021\n              value: AKIAABCDEFGHIJKLMNOP\n"),))
case("1022-configmap-secret", "K8S1022", (), extra=("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\n  namespace: shop\ndata:\n  api_token: abcdef0123 # !K8S1022\n  mode: fast\n",))
case("1023-inline-secret", "K8S1023", (), extra=("apiVersion: v1\nkind: Secret\nmetadata:\n  name: creds\n  namespace: shop\nstringData: # !K8S1023\n  password: fake-secret-value\n",))
# ---- service account, pull policy
case("1024-automount-true", "K8S1024", (("      automountServiceAccountToken: false\n", "      automountServiceAccountToken: true # !K8S1024\n"),))
case("1024-automount-default", "K8S1024", (("      automountServiceAccountToken: false\n", ""), ("automountServiceAccountToken: false\n---\n", "---\n"), (POD_SPEC, "    spec: # !K8S1024\n      serviceAccountName: web\n")))
case("1025-no-pod-securitycontext", "K8S1025", ((POD_SC, ""), (POD_SPEC, "    spec: # !K8S1025\n      serviceAccountName: web\n")))
case("1027-invalid-pull-policy", "K8S1027", (after_image("          imagePullPolicy: Sometimes # !K8S1027\n"),))
case("1027-ifnotpresent-latest", "K8S1027", (img("registry.example.com/shop/web:latest\n          imagePullPolicy: IfNotPresent # !K8S1027"),))
case("1037-default-sa", "K8S1037", (("      serviceAccountName: web\n", ""), (POD_SPEC.replace("      serviceAccountName: web\n", "      automountServiceAccountToken: false\n"), "    spec: # !K8S1037\n      automountServiceAccountToken: false\n")))
# ---- services, ingress
case("1028-loadbalancer", "K8S1028", (("  type: ClusterIP\n", "  type: LoadBalancer # !K8S1028\n"),))
case("1029-nodeport", "K8S1029", (("  type: ClusterIP\n", "  type: NodePort # !K8S1029\n"),))
case("1040-external-ips", "K8S1040", (("  type: ClusterIP\n", "  type: ClusterIP\n  externalIPs: [192.0.2.10] # !K8S1040\n"),))
case("1035-ingress-no-tls", "K8S1035", (), extra=("apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: web\n  namespace: shop\nspec: # !K8S1035\n  rules:\n    - host: shop.example.com\n      http:\n        paths:\n          - path: /\n            pathType: Prefix\n            backend:\n              service:\n                name: web\n                port:\n                  number: 80\n",))
# ---- cronjob, pods, deprecations, duplicates
case("1031-cron-concurrency-default", "K8S1031", (), extra=(CRONJOB % (" # !K8S1031", "  successfulJobsHistoryLimit: 3\n  failedJobsHistoryLimit: 3\n", HEX),))
case("1031-cron-concurrency-allow", "K8S1031", (), extra=(CRONJOB % ("", "  concurrencyPolicy: Allow # !K8S1031\n  successfulJobsHistoryLimit: 3\n  failedJobsHistoryLimit: 3\n", HEX),))
case("1032-cron-history", "K8S1032", (), extra=(CRONJOB % (" # !K8S1032", "  concurrencyPolicy: Forbid\n", HEX),))
case("1033-removed-apiversion", "K8S1033", (("apiVersion: apps/v1\n", "apiVersion: apps/v1beta2 # !K8S1033\n"),))
case("1033-removed-pdb", "K8S1033", (("apiVersion: policy/v1\n", "apiVersion: policy/v1beta1 # !K8S1033\n"),))
case("1036-bare-pod", "K8S1036", (), extra=(f"apiVersion: v1\nkind: Pod # !K8S1036\nmetadata:\n  name: tool\n  namespace: shop\n  labels:\n    app: tool\nspec:\n  serviceAccountName: web\n  restartPolicy: Never\n  automountServiceAccountToken: false\n{POD_SC_2}  containers:\n    - name: t\n      image: registry.example.com/t:1@sha256:{HEX}\n",))
case("1039-duplicate-key", "K8S1039", (("  replicas: 2\n", "  replicas: 2\n  replicas: 3 # !K8S1039\n"),))


@pytest.mark.parametrize("name", sorted(CASES))
def test_bad_manifest_reports_rule_at_marked_line(lint_text, name):
    rule, drop, extra, edits = CASES[name]
    text = build_base(drop=drop, extra=extra, edits=edits)
    marks = marked_lines(text, rule)
    assert marks, f"case {name} has no marker for {rule}"
    found = lint_text(text)
    hits = [f for f in found if f.rule == rule]
    assert hits, f"{rule} not reported; got {[(f.rule, f.line) for f in found]}"
    assert any(f.line in marks for f in hits), f"{rule} reported at {[f.line for f in hits]}, expected one of {marks}"
    for f in hits:
        assert f.fix.strip() and f.message.strip()
        assert f.severity in ("error", "warning", "info")


def test_at_least_forty_five_bad_cases():
    assert len(CASES) >= 45


@pytest.mark.parametrize(
    ("name", "rule", "severity"),
    [
        ("1006-escalation-true", "K8S1006", "error"),
        ("1006-escalation-absent", "K8S1006", "warning"),
        ("1011-sys-admin", "K8S1011", "error"),
        ("1011-net-admin-warning", "K8S1011", "warning"),
        ("1014-host-path", "K8S1014", "warning"),
        ("1014-host-path-sensitive", "K8S1014", "error"),
        ("1020-explicit-default", "K8S1020", "warning"),
        ("1020-namespace-omitted", "K8S1020", "info"),
        ("1024-automount-true", "K8S1024", "warning"),
        ("1024-automount-default", "K8S1024", "info"),
        ("1027-invalid-pull-policy", "K8S1027", "error"),
        ("1033-removed-apiversion", "K8S1033", "error"),
        ("1004-no-digest", "K8S1004", "info"),
    ],
)
def test_severity_of_variants(lint_text, name, rule, severity):
    _, drop, extra, edits = CASES[name]
    found = [f for f in lint_text(build_base(drop=drop, extra=extra, edits=edits)) if f.rule == rule]
    assert found and all(f.severity == severity for f in found), [(f.severity, f.message) for f in found]
