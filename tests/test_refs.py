"""Cross-resource checks (K8S2xxx): each case mutates the clean base and marks the expected line."""

from __future__ import annotations

import pytest

from conftest import DIGEST, build_base, marked_lines

REFS: dict[str, tuple[str, tuple[str, ...], tuple[str, ...], tuple[tuple[str, str], ...]]] = {}


def case(name: str, rule: str, edits: tuple[tuple[str, str], ...] = (), drop: tuple[str, ...] = (), extra: tuple[str, ...] = ()) -> None:
    REFS[name] = (rule, drop, extra, edits)


def after_image(extra: str) -> tuple[str, str]:
    old = f"          image: registry.example.com/shop/web:1.4.2@{DIGEST}\n"
    return old, old + extra


CM = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n  namespace: shop\ndata:\n  mode: fast\n"
STS = """\
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
  namespace: shop
spec:
  serviceName: db-headless # !K8S2014
  replicas: 1
  selector:
    matchLabels:
      app: db
  template:
    metadata:
      labels:
        app: db
    spec:
      containers:
        - name: db
          image: postgres:16
"""
ING = """\
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: shop
spec:
  tls:
    - hosts: [shop.example.com]
      secretName: web-tls
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: # !%s
              service:
                name: %s
                port:
                  %s
"""

case("2001-selector-mismatch", "K8S2001", (("  selector:\n    matchLabels:\n      app: web\n  template:", "  selector: # !K8S2001\n    matchLabels:\n      app: api\n  template:"),))
case("2001-selector-missing", "K8S2001", (("  selector:\n    matchLabels:\n      app: web\n  template:", "  template:"), ("spec:\n  replicas: 2\n", "spec: # !K8S2001\n  replicas: 2\n")))
case("2002-service-selects-nothing", "K8S2002", (("  selector:\n    app: web\n  ports:", "  selector: # !K8S2002\n    app: nope\n  ports:"),))
case("2003-ingress-service-missing", "K8S2003", (), extra=(ING % ("K8S2003", "ghost", "number: 80"),))
case("2004-ingress-port-missing", "K8S2004", (), extra=(ING % ("K8S2004", "web", "number: 9999"),))
case("2004-ingress-named-port-missing", "K8S2004", (), extra=(ING % ("K8S2004", "web", "name: grpc"),))
case("2005-configmap-missing", "K8S2005", (after_image("          envFrom:\n            - configMapRef: # !K8S2005\n                name: absent\n"),), extra=(CM,))
case("2006-secret-missing", "K8S2006", (after_image("          env:\n            - name: DB_PASSWORD\n              valueFrom:\n                secretKeyRef: # !K8S2006\n                  name: db-creds\n                  key: password\n"),))
case("2007-pvc-missing", "K8S2007", (("      containers:\n", "      volumes:\n        - name: data\n          persistentVolumeClaim: # !K8S2007\n            claimName: data\n      containers:\n"),
                                      after_image("          volumeMounts:\n            - name: data\n              mountPath: /data\n")))
case("2008-serviceaccount-missing", "K8S2008", (("      serviceAccountName: web\n", "      serviceAccountName: ghost # !K8S2008\n"),), drop=("sa",))
case("2009-key-missing", "K8S2009", (after_image("          env:\n            - name: MODE\n              valueFrom:\n                configMapKeyRef: # !K8S2009\n                  name: settings\n                  key: speed\n"),), extra=(CM,))
case("2010-targetport-number", "K8S2010", (("      targetPort: http\n", "      targetPort: 9999\n"), ("    - name: http\n      port: 80\n", "    - name: http # !K8S2010\n      port: 80\n")))
case("2010-targetport-name", "K8S2010", (("      targetPort: http\n", "      targetPort: nope\n"), ("    - name: http\n      port: 80\n", "    - name: http # !K8S2010\n      port: 80\n")))
case("2011-hpa-target-missing", "K8S2011", (), extra=("apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\nmetadata:\n  name: web\n  namespace: shop\nspec:\n  scaleTargetRef: # !K8S2011\n    apiVersion: apps/v1\n    kind: Deployment\n    name: gone\n  minReplicas: 2\n  maxReplicas: 4\n",))
case("2012-pdb-selects-nothing", "K8S2012", (("  minAvailable: 1\n  selector:\n    matchLabels:\n      app: web\n", "  minAvailable: 1\n  selector: # !K8S2012\n    matchLabels:\n      app: other\n"),))
case("2013-duplicate", "K8S2013", (), extra=("apiVersion: v1\nkind: Service\nmetadata:\n  name: web # !K8S2013\n  namespace: shop\nspec:\n  selector:\n    app: web\n  ports:\n    - port: 81\n",))
case("2014-statefulset-service", "K8S2014", (), extra=(STS,))
case("2015-rolebinding-role-missing", "K8S2015", (), extra=("apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: rb\n  namespace: shop\nroleRef: # !K8S2015\n  apiGroup: rbac.authorization.k8s.io\n  kind: Role\n  name: absent\nsubjects:\n  - kind: ServiceAccount\n    name: web\n    namespace: shop\n",))
case("2016-service-port-names", "K8S2016", (("  ports:\n    - name: http\n      port: 80\n      targetPort: http\n", "  ports:\n    - name: http\n      port: 80\n      targetPort: http\n    - port: 81 # !K8S2016\n"),))
case("2017-volume-mount-unknown", "K8S2017", (after_image("          volumeMounts:\n            - name: cache # !K8S2017\n              mountPath: /cache\n"),))


@pytest.mark.parametrize("name", sorted(REFS))
def test_reference_problem_reported_at_marked_line(lint_text, name):
    rule, drop, extra, edits = REFS[name]
    text = build_base(drop=drop, extra=extra, edits=edits)
    marks = marked_lines(text, rule)
    assert marks
    found = lint_text(text, "K8S2")
    hits = [f for f in found if f.rule == rule]
    assert hits, f"{rule} not reported; got {[(f.rule, f.line, f.message) for f in found]}"
    assert any(f.line in marks for f in hits), (rule, [f.line for f in hits], marks)


def test_at_least_fourteen_reference_cases():
    assert len(REFS) >= 14


def test_optional_references_are_not_reported(lint_text):
    text = build_base(edits=(after_image("          envFrom:\n            - configMapRef:\n                name: absent\n                optional: true\n"),))
    assert [f for f in lint_text(text, "K8S2") if f.rule == "K8S2005"] == []


def test_missing_secret_is_info_missing_configmap_is_warning_when_others_exist(lint_text):
    s = build_base(edits=(after_image("          env:\n            - name: P\n              valueFrom:\n                secretKeyRef:\n                  name: x\n                  key: k\n"),))
    assert {f.severity for f in lint_text(s, "K8S2") if f.rule == "K8S2006"} == {"info"}
    c = build_base(edits=(after_image("          envFrom:\n            - configMapRef:\n                name: absent\n"),), extra=(CM,))
    assert {f.severity for f in lint_text(c, "K8S2") if f.rule == "K8S2005"} == {"warning"}
    alone = build_base(edits=(after_image("          envFrom:\n            - configMapRef:\n                name: absent\n"),))
    assert {f.severity for f in lint_text(alone, "K8S2") if f.rule == "K8S2005"} == {"info"}


def test_objects_without_namespace_match_any_namespace(lint_text):
    # a Service with no metadata.namespace still finds the pods in "shop" (it lands wherever you apply it)
    text = build_base(edits=(("kind: Service\nmetadata:\n  name: web\n  namespace: shop\n", "kind: Service\nmetadata:\n  name: web\n"),))
    assert lint_text(text, "K8S2") == []


def test_cross_file_references_resolve_in_directory_mode(load):
    from kubelint_mcp.registry import run_rules

    files = {"deploy.yaml": build_base(drop=("service",)), "svc.yaml": build_base().split("---\n")[3]}
    rs = load(files)
    assert [f for f in run_rules(rs, "K8S2", frozenset()) if f.rule == "K8S2002"] == []
    only_deploy = load({"deploy.yaml": files["deploy.yaml"], "svc.yaml": files["svc.yaml"].replace("app: web", "app: other")})
    assert any(f.rule == "K8S2002" and f.file == "svc.yaml" for f in run_rules(only_deploy, "K8S2", frozenset()))
