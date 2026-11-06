"""Shared helpers: write real files to a temp dir and lint them through the real code path."""

from __future__ import annotations

import os
import re
from collections.abc import Callable

import pytest

from kubelint_mcp import server  # noqa: F401  (registers every rule)
from kubelint_mcp.files import Sandbox
from kubelint_mcp.findings import Finding
from kubelint_mcp.model import ResourceSet, load_set
from kubelint_mcp.registry import run_rules

DIGEST = "sha256:" + "a" * 64

# A hardened, complete app: lints clean for K8S1xxx, K8S2xxx and K8S3xxx. Every bad-manifest test mutates
# exactly this text, so a finding can only come from the mutation.
BASE_DOCS: dict[str, str] = {
    "namespace": """\
apiVersion: v1
kind: Namespace
metadata:
  name: shop
  labels:
    pod-security.kubernetes.io/enforce: restricted
""",
    "sa": """\
apiVersion: v1
kind: ServiceAccount
metadata:
  name: web
  namespace: shop
automountServiceAccountToken: false
""",
    "deployment": f"""\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
  labels:
    app: web
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      serviceAccountName: web
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: registry.example.com/shop/web:1.4.2@{DIGEST}
          ports:
            - name: http
              containerPort: 8080
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              memory: 256Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
          readinessProbe:
            httpGet:
              path: /ready
              port: http
""",
    "service": """\
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: shop
spec:
  type: ClusterIP
  selector:
    app: web
  ports:
    - name: http
      port: 80
      targetPort: http
""",
    "pdb": """\
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web
  namespace: shop
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: web
""",
    "netpol": """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: shop
spec:
  podSelector: {}
  policyTypes: [Ingress]
""",
}

PROBES = """\
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
          readinessProbe:
            httpGet:
              path: /ready
              port: http
"""
RESOURCES = """\
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              memory: 256Mi
"""
POD_SC = """\
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
"""


def build_base(drop: tuple[str, ...] = (), extra: tuple[str, ...] = (), edits: tuple[tuple[str, str], ...] = ()) -> str:
    docs = [t for k, t in BASE_DOCS.items() if k not in drop] + list(extra)
    text = "---\n".join(docs)
    for old, new in edits:
        assert text.count(old) == 1, f"edit target must be unique ({text.count(old)} matches): {old!r}"
        text = text.replace(old, new)
    return text


MARK = re.compile(r"#\s*!(K8S\d{4})")


def marked_lines(text: str, rule: str) -> list[int]:
    return [i + 1 for i, ln in enumerate(text.split("\n")) if (m := MARK.search(ln)) and m.group(1) == rule]


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def lint_text(tmp_path) -> Callable[..., list[Finding]]:  # type: ignore[no-untyped-def]
    """lint_text(yaml_text, prefix="K8S1", disabled=...) -> findings (through a real file and the sandbox)."""
    counter = {"n": 0}

    def run(text: str, prefix: str = "K8S1", disabled: frozenset[str] = frozenset(), name: str = "m.yaml") -> list[Finding]:
        counter["n"] += 1
        d = tmp_path / f"case{counter['n']}"
        d.mkdir()
        write(str(d / name), text)
        rs = load_set(Sandbox(str(d)), name)
        return run_rules(rs, prefix, disabled)

    return run


@pytest.fixture
def load(tmp_path) -> Callable[..., ResourceSet]:  # type: ignore[no-untyped-def]
    counter = {"n": 0}

    def run(files: dict[str, str], target: str = ".") -> ResourceSet:
        counter["n"] += 1
        d = tmp_path / f"set{counter['n']}"
        d.mkdir()
        for rel, content in files.items():
            write(str(d / rel), content)
        return load_set(Sandbox(str(d)), target)

    return run
