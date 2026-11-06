"""The embedded table of removed/deprecated API versions: structure, known facts, and the lint rule over every entry."""

from __future__ import annotations

import pytest

from kubelint_mcp import deprecations as dep
from kubelint_mcp.deprecations import ALL, TARGET_VERSION, lookup, version_tuple


def test_table_is_internally_consistent():
    seen = set()
    for e in ALL:
        assert (e.api_version, e.kind) not in seen, f"duplicate entry {e.api_version} {e.kind}"
        seen.add((e.api_version, e.kind))
        assert e.replacement.strip(), e
        assert "/" in e.api_version or e.api_version == "v1"
        assert e.removed_in or e.deprecated_in, e
        if e.removed_in and e.deprecated_in:
            assert version_tuple(e.removed_in) > version_tuple(e.deprecated_in), e
        for v in (e.removed_in, e.deprecated_in):
            if v:
                major, minor = version_tuple(v)
                assert major == 1 and 0 <= minor <= 40
        if e.removed:
            # a removed API must never be proposed as its own replacement
            assert not e.replacement.startswith(e.api_version + " "), e


@pytest.mark.parametrize(
    ("api", "kind", "removed", "replacement"),
    [
        ("extensions/v1beta1", "Deployment", "1.16", "apps/v1"),
        ("extensions/v1beta1", "Ingress", "1.22", "networking.k8s.io/v1"),
        ("extensions/v1beta1", "NetworkPolicy", "1.16", "networking.k8s.io/v1"),
        ("apps/v1beta1", "Deployment", "1.16", "apps/v1"),
        ("apps/v1beta2", "StatefulSet", "1.16", "apps/v1"),
        ("networking.k8s.io/v1beta1", "Ingress", "1.22", "networking.k8s.io/v1"),
        ("policy/v1beta1", "PodDisruptionBudget", "1.25", "policy/v1"),
        ("policy/v1beta1", "PodSecurityPolicy", "1.25", None),
        ("batch/v1beta1", "CronJob", "1.25", "batch/v1"),
        ("autoscaling/v2beta1", "HorizontalPodAutoscaler", "1.25", "autoscaling/v2"),
        ("autoscaling/v2beta2", "HorizontalPodAutoscaler", "1.26", "autoscaling/v2"),
        ("rbac.authorization.k8s.io/v1beta1", "ClusterRole", "1.22", "rbac.authorization.k8s.io/v1"),
        ("admissionregistration.k8s.io/v1beta1", "ValidatingWebhookConfiguration", "1.22", "admissionregistration.k8s.io/v1"),
        ("apiextensions.k8s.io/v1beta1", "CustomResourceDefinition", "1.22", "apiextensions.k8s.io/v1"),
        ("storage.k8s.io/v1beta1", "CSIDriver", "1.22", "storage.k8s.io/v1"),
        ("storage.k8s.io/v1beta1", "CSIStorageCapacity", "1.27", "storage.k8s.io/v1"),
        ("discovery.k8s.io/v1beta1", "EndpointSlice", "1.25", "discovery.k8s.io/v1"),
        ("flowcontrol.apiserver.k8s.io/v1beta3", "FlowSchema", "1.32", "flowcontrol.apiserver.k8s.io/v1"),
        ("certificates.k8s.io/v1beta1", "CertificateSigningRequest", "1.22", "certificates.k8s.io/v1"),
        ("coordination.k8s.io/v1beta1", "Lease", "1.22", "coordination.k8s.io/v1"),
        ("node.k8s.io/v1beta1", "RuntimeClass", "1.25", "node.k8s.io/v1"),
    ],
)
def test_known_facts(api, kind, removed, replacement):
    e = lookup(api, kind)
    assert e is not None
    assert e.removed_in == removed
    assert e.removed
    if replacement:
        assert e.replacement == replacement
    else:
        assert e.replacement.startswith("none")


def test_current_apis_are_not_flagged():
    for api, kind in [("apps/v1", "Deployment"), ("batch/v1", "CronJob"), ("networking.k8s.io/v1", "Ingress"), ("policy/v1", "PodDisruptionBudget"),
                      ("autoscaling/v2", "HorizontalPodAutoscaler"), ("rbac.authorization.k8s.io/v1", "Role"), ("v1", "Pod"), ("v1", "Service"),
                      ("storage.k8s.io/v1", "CSIDriver"), ("flowcontrol.apiserver.k8s.io/v1", "FlowSchema")]:
        assert lookup(api, kind) is None, (api, kind)


def test_wildcard_applies_to_unknown_kinds_in_removed_groups():
    e = lookup("apps/v1beta1", "SomethingNew")
    assert e is not None and e.kind == "*" and e.removed_in == "1.16"
    assert lookup("apps/v1", "SomethingNew") is None


def test_deprecated_but_still_served_is_not_removed():
    e = lookup("v1", "Endpoints")
    assert e is not None and not e.removed and e.deprecated_in == "1.33"
    assert dep.describe(e, "Endpoints").endswith("still served")


def test_target_version_is_sane():
    assert version_tuple(TARGET_VERSION) >= (1, 32)


def _entries():
    for e in ALL:
        kind = e.kind if e.kind != "*" else "Widget"
        yield pytest.param(e, kind, id=f"{e.api_version}-{kind}")


@pytest.mark.parametrize(("entry", "kind"), list(_entries()))
def test_every_entry_is_reported_on_the_apiversion_line(lint_text, entry, kind):
    text = f"# header\napiVersion: {entry.api_version}\nkind: {kind}\nmetadata:\n  name: x\n  namespace: n\n"
    found = [f for f in lint_text(text) if f.rule == "K8S1033"]
    assert len(found) == 1
    f = found[0]
    assert f.line == 2
    assert f.severity == ("error" if entry.removed else "warning")
    assert entry.replacement in f.message
    if entry.removed_in:
        assert entry.removed_in in f.message
