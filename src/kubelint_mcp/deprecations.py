"""Kubernetes API versions that were deprecated and/or removed, with the replacement.

Sources: the Kubernetes "Deprecated API Migration Guide" and the per-release deprecation notes.
Versions are minor releases ("1.25" means v1.25). `safe_rename` is True only when changing the
apiVersion string alone is a valid migration (the schema did not change in a way that needs edits);
suggest_fixes applies only those.

TARGET_VERSION is the newest release this table knows about. Anything removed at or before it is an
error; an API that is only deprecated is a warning.
"""

from __future__ import annotations

from dataclasses import dataclass

TARGET_VERSION = "1.34"


@dataclass(frozen=True)
class Deprecation:
    api_version: str
    kind: str  # "*" = every kind in this apiVersion
    deprecated_in: str | None
    removed_in: str | None
    replacement: str  # the apiVersion to use, or free text when there is none
    note: str = ""
    safe_rename: bool = False

    @property
    def removed(self) -> bool:
        return self.removed_in is not None and version_tuple(self.removed_in) <= version_tuple(TARGET_VERSION)


def version_tuple(v: str) -> tuple[int, int]:
    major, _, minor = v.partition(".")
    return int(major), int(minor)


def _d(api: str, kind: str, dep: str | None, rem: str | None, repl: str, note: str = "", safe: bool = False) -> Deprecation:
    return Deprecation(api, kind, dep, rem, repl, note, safe)


_ENTRIES: tuple[Deprecation, ...] = (
    # extensions/v1beta1: workloads left in 1.16, Ingress in 1.22.
    _d("extensions/v1beta1", "Deployment", "1.8", "1.16", "apps/v1", "apps/v1 requires spec.selector to be set."),
    _d("extensions/v1beta1", "DaemonSet", "1.8", "1.16", "apps/v1", "apps/v1 requires spec.selector to be set."),
    _d("extensions/v1beta1", "ReplicaSet", "1.8", "1.16", "apps/v1", "apps/v1 requires spec.selector to be set."),
    _d("extensions/v1beta1", "NetworkPolicy", "1.8", "1.16", "networking.k8s.io/v1", safe=True),
    _d("extensions/v1beta1", "PodSecurityPolicy", "1.10", "1.16", "none: PodSecurityPolicy itself was removed in 1.25; use Pod Security Admission",
       "Moving to policy/v1beta1 only delays the problem; PSP is gone in 1.25."),
    _d("extensions/v1beta1", "Ingress", "1.14", "1.22", "networking.k8s.io/v1",
       "networking.k8s.io/v1 needs pathType on every path and backend.service.name/port instead of serviceName/servicePort."),
    _d("extensions/v1beta1", "*", "1.8", "1.16", "the apps/v1 or networking.k8s.io/v1 equivalent"),
    # apps/v1beta1, apps/v1beta2: all removed in 1.16.
    _d("apps/v1beta1", "Deployment", "1.9", "1.16", "apps/v1", "apps/v1 requires spec.selector; the default rollback and revision limits changed."),
    _d("apps/v1beta1", "StatefulSet", "1.9", "1.16", "apps/v1", "apps/v1 requires spec.selector and defaults updateStrategy to RollingUpdate."),
    _d("apps/v1beta1", "*", "1.9", "1.16", "apps/v1"),
    _d("apps/v1beta2", "Deployment", "1.9", "1.16", "apps/v1", "apps/v1 requires spec.selector.", safe=False),
    _d("apps/v1beta2", "StatefulSet", "1.9", "1.16", "apps/v1", "apps/v1 requires spec.selector."),
    _d("apps/v1beta2", "DaemonSet", "1.9", "1.16", "apps/v1", "apps/v1 requires spec.selector."),
    _d("apps/v1beta2", "ReplicaSet", "1.9", "1.16", "apps/v1", "apps/v1 requires spec.selector."),
    _d("apps/v1beta2", "*", "1.9", "1.16", "apps/v1"),
    # networking.k8s.io
    _d("networking.k8s.io/v1beta1", "Ingress", "1.19", "1.22", "networking.k8s.io/v1",
       "networking.k8s.io/v1 needs pathType on every path and backend.service.name/port instead of serviceName/servicePort."),
    _d("networking.k8s.io/v1beta1", "IngressClass", "1.19", "1.22", "networking.k8s.io/v1", safe=True),
    # policy
    _d("policy/v1beta1", "PodSecurityPolicy", "1.21", "1.25", "none: use Pod Security Admission (namespace label pod-security.kubernetes.io/enforce)"),
    _d("policy/v1beta1", "PodDisruptionBudget", "1.21", "1.25", "policy/v1",
       "In policy/v1 an empty selector matches every pod in the namespace (in v1beta1 it matched none).", safe=True),
    # batch
    _d("batch/v1beta1", "CronJob", "1.21", "1.25", "batch/v1", safe=True),
    _d("batch/v1beta1", "JobTemplate", "1.21", "1.25", "none: JobTemplate was removed with batch/v1beta1"),
    _d("batch/v2alpha1", "CronJob", None, "1.21", "batch/v1", safe=True),
    # autoscaling
    _d("autoscaling/v2beta1", "HorizontalPodAutoscaler", "1.22", "1.25", "autoscaling/v2",
       "autoscaling/v2 renamed targetAverageUtilization/targetAverageValue to target.type/averageUtilization/averageValue."),
    _d("autoscaling/v2beta2", "HorizontalPodAutoscaler", "1.23", "1.26", "autoscaling/v2", safe=True),
    # rbac
    _d("rbac.authorization.k8s.io/v1beta1", "Role", "1.17", "1.22", "rbac.authorization.k8s.io/v1", safe=True),
    _d("rbac.authorization.k8s.io/v1beta1", "ClusterRole", "1.17", "1.22", "rbac.authorization.k8s.io/v1", safe=True),
    _d("rbac.authorization.k8s.io/v1beta1", "RoleBinding", "1.17", "1.22", "rbac.authorization.k8s.io/v1", safe=True),
    _d("rbac.authorization.k8s.io/v1beta1", "ClusterRoleBinding", "1.17", "1.22", "rbac.authorization.k8s.io/v1", safe=True),
    _d("rbac.authorization.k8s.io/v1alpha1", "*", None, "1.22", "rbac.authorization.k8s.io/v1", safe=True),
    # admission, apiextensions, apiregistration
    _d("admissionregistration.k8s.io/v1beta1", "ValidatingWebhookConfiguration", "1.16", "1.22", "admissionregistration.k8s.io/v1",
       "v1 requires sideEffects, admissionReviewVersions and a structural matchPolicy; failurePolicy and timeoutSeconds defaults changed."),
    _d("admissionregistration.k8s.io/v1beta1", "MutatingWebhookConfiguration", "1.16", "1.22", "admissionregistration.k8s.io/v1",
       "v1 requires sideEffects, admissionReviewVersions and a structural matchPolicy; failurePolicy and timeoutSeconds defaults changed."),
    _d("apiextensions.k8s.io/v1beta1", "CustomResourceDefinition", "1.16", "1.22", "apiextensions.k8s.io/v1",
       "v1 requires a structural schema per version (spec.versions[].schema) and spec.preserveUnknownFields: false."),
    _d("apiregistration.k8s.io/v1beta1", "APIService", "1.19", "1.22", "apiregistration.k8s.io/v1", safe=True),
    # certificates, coordination, scheduling, auth
    _d("certificates.k8s.io/v1beta1", "CertificateSigningRequest", "1.19", "1.22", "certificates.k8s.io/v1",
       "v1 requires spec.signerName and a usages list."),
    _d("coordination.k8s.io/v1beta1", "Lease", "1.19", "1.22", "coordination.k8s.io/v1", safe=True),
    _d("scheduling.k8s.io/v1beta1", "PriorityClass", "1.14", "1.22", "scheduling.k8s.io/v1", safe=True),
    _d("scheduling.k8s.io/v1alpha1", "PriorityClass", None, "1.22", "scheduling.k8s.io/v1", safe=True),
    _d("authentication.k8s.io/v1beta1", "TokenReview", "1.19", "1.22", "authentication.k8s.io/v1", safe=True),
    _d("authorization.k8s.io/v1beta1", "SubjectAccessReview", "1.19", "1.22", "authorization.k8s.io/v1", safe=True),
    _d("authorization.k8s.io/v1beta1", "LocalSubjectAccessReview", "1.19", "1.22", "authorization.k8s.io/v1", safe=True),
    _d("authorization.k8s.io/v1beta1", "SelfSubjectAccessReview", "1.19", "1.22", "authorization.k8s.io/v1", safe=True),
    # storage
    _d("storage.k8s.io/v1beta1", "CSIDriver", "1.19", "1.22", "storage.k8s.io/v1", safe=True),
    _d("storage.k8s.io/v1beta1", "CSINode", "1.17", "1.22", "storage.k8s.io/v1", safe=True),
    _d("storage.k8s.io/v1beta1", "StorageClass", "1.19", "1.22", "storage.k8s.io/v1", safe=True),
    _d("storage.k8s.io/v1beta1", "VolumeAttachment", "1.19", "1.22", "storage.k8s.io/v1", safe=True),
    _d("storage.k8s.io/v1beta1", "CSIStorageCapacity", "1.24", "1.27", "storage.k8s.io/v1", safe=True),
    # discovery, events, node
    _d("discovery.k8s.io/v1beta1", "EndpointSlice", "1.21", "1.25", "discovery.k8s.io/v1",
       "v1 renamed topology to nodeName/zone and the deprecatedTopology field."),
    _d("events.k8s.io/v1beta1", "Event", "1.19", "1.25", "events.k8s.io/v1",
       "v1 renamed deprecatedSource/deprecatedFirstTimestamp and made series.count required."),
    _d("node.k8s.io/v1beta1", "RuntimeClass", "1.22", "1.25", "node.k8s.io/v1", safe=True),
    _d("node.k8s.io/v1alpha1", "RuntimeClass", None, "1.22", "node.k8s.io/v1"),
    # flowcontrol
    _d("flowcontrol.apiserver.k8s.io/v1beta1", "FlowSchema", "1.23", "1.26", "flowcontrol.apiserver.k8s.io/v1", safe=True),
    _d("flowcontrol.apiserver.k8s.io/v1beta1", "PriorityLevelConfiguration", "1.23", "1.26", "flowcontrol.apiserver.k8s.io/v1",
       "In v1 spec.limited.nominalConcurrencyShares replaces assuredConcurrencyShares."),
    _d("flowcontrol.apiserver.k8s.io/v1beta2", "FlowSchema", "1.26", "1.29", "flowcontrol.apiserver.k8s.io/v1", safe=True),
    _d("flowcontrol.apiserver.k8s.io/v1beta2", "PriorityLevelConfiguration", "1.26", "1.29", "flowcontrol.apiserver.k8s.io/v1",
       "In v1 spec.limited.nominalConcurrencyShares replaces assuredConcurrencyShares."),
    _d("flowcontrol.apiserver.k8s.io/v1beta3", "FlowSchema", "1.29", "1.32", "flowcontrol.apiserver.k8s.io/v1", safe=True),
    _d("flowcontrol.apiserver.k8s.io/v1beta3", "PriorityLevelConfiguration", "1.29", "1.32", "flowcontrol.apiserver.k8s.io/v1", safe=True),
    # still served, but deprecated
    _d("v1", "Endpoints", "1.33", None, "discovery.k8s.io/v1 EndpointSlice",
       "The core v1 Endpoints API is deprecated since 1.33 in favour of EndpointSlice; it is still served."),
    _d("v1", "ComponentStatus", "1.19", None, "none: query the control plane health endpoints (/livez, /readyz)",
       "ComponentStatus is deprecated since 1.19 and unreliable; it is still served."),
)

BY_KEY: dict[tuple[str, str], Deprecation] = {(e.api_version, e.kind): e for e in _ENTRIES}
ALL: tuple[Deprecation, ...] = _ENTRIES


def lookup(api_version: str, kind: str) -> Deprecation | None:
    """The deprecation entry for this apiVersion + kind (exact kind first, then the apiVersion wildcard)."""
    hit = BY_KEY.get((api_version, kind))
    if hit is not None:
        return hit
    return BY_KEY.get((api_version, "*"))


def describe(d: Deprecation, kind: str) -> str:
    if d.removed:
        when = f"removed in Kubernetes {d.removed_in}"
        if d.deprecated_in:
            when += f" (deprecated since {d.deprecated_in})"
        head = f"{d.api_version} {kind} was {when}; a current API server rejects it"
    else:
        head = f"{d.api_version} {kind} is deprecated since Kubernetes {d.deprecated_in} but still served"
    return head
