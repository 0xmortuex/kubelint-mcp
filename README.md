# kubelint-mcp

An MCP server that lets an AI **lint and explain Kubernetes manifests statically**: plain YAML,
multi-document files, `kind: List` wrappers and `helm template` output. Every finding has a rule ID, a
severity, `file:line` and a concrete fix. It never contacts a cluster, never applies anything, and needs
neither `kubectl` nor any other binary.

**How it differs from what exists.** The Kubernetes MCP servers I could find either talk to a live cluster
(kubectl-style servers) or wrap external tools: [kube-lint-mcp](https://github.com/sophotechlabs/kube-lint-mcp)
ships kubeconform, kubectl and helm inside a Docker image and validates schemas. This server is pure Python
(`mcp` + `pyyaml`), runs fully offline, and goes after what schema validation cannot see: security posture
(privileged, root, capabilities, host access, docker.sock), cross-object mistakes (a Service whose selector
matches nothing, an Ingress pointing at a missing port, a `configMapKeyRef` to a key that does not exist), RBAC
reasoning, a hand-checked table of removed and deprecated API versions with the release that dropped them, and a
unified-diff preview of the safe fixes. Secret values are never echoed back to the model: names and lengths only.

## Install

Claude Code:

```bash
claude mcp add kubelint -- uvx kubelint-mcp --dir .
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "kubelint": {
      "command": "uvx",
      "args": ["kubelint-mcp", "--dir", "C:\\path\\to\\your\\manifests"]
    }
  }
}
```

Without uv: `pip install kubelint-mcp`, then run `kubelint-mcp --dir /path/to/manifests`.

| Flag | Meaning |
|------|---------|
| `--dir PATH` | Only files inside this directory can be read (default: the current directory). |
| `--disable IDS` | Comma-separated rule ids to turn off, e.g. `--disable K8S1004,K8S1018`. Repeatable. |

Silence a single finding in the file itself with a comment on the line above it (or at the end of the line):

```yaml
containers:
  # kubelint-ignore: K8S1009, K8S1010
  - name: app            # the whole container item is covered
```

A comment at the very top of a document (or right after `---`) covers that whole document.

## Tools

| Tool | What it does |
|------|--------------|
| `k8s_overview(path)` | Every object by kind and namespace, workloads with replicas, images and ports, Services and what they select, Ingress routes, host-network workloads. |
| `lint_manifests(path)` | 41 rules (K8S1000-K8S1040): resources, images, security context, host access, probes, replicas, namespaces, secrets, exposure, CronJob settings, removed APIs. |
| `check_references(path)` | 17 cross-resource rules (K8S2001-K8S2017) over the files you pass. |
| `rbac_review(path)` | 11 RBAC rules (K8S3001-K8S3011) plus a list of roles and bindings. |
| `explain_resource(path, kind, name, namespace="")` | Plain-English account of one object: what it does, effective security posture, dependencies, what reaches it, findings. |
| `suggest_fixes(path)` | Unified diff (as text, never written) of the safe mechanical fixes for one file, verified by re-linting the patched text. |
| `values_review(path)` | Review a Helm `values.yaml` (K8S4001-K8S4007); credentials are redacted. |
| `render_helm(chart_dir, ...)` | **Opt-in.** Runs the local `helm template` (argument list, 60 s timeout, no cluster) and lints the output in memory. Refuses unless `allow_exec=true`. |

`path` is a YAML file or a directory of them (relative to `--dir`, or absolute inside it). Directory mode
skips YAML that is not a Kubernetes object (`Chart.yaml`, `values.yaml`) and unrendered Helm templates, and says
how many it skipped. Custom resources (Certificate, ExternalSecret, ...) are skipped quietly with a count, but
their `apiVersion` is still checked against the removed-API table.

## Try asking

- "Give me an overview of the manifests in `deploy/`."
- "Lint `deploy/` and fix everything that is safe, then show me what is left."
- "Is anything in this Deployment dangerous? Explain it to me in plain English."
- "Does my Service actually select my pods? Does the Ingress point at a real port?"
- "Review the RBAC in `rbac.yaml`. Who can read secrets?"
- "Will these manifests still apply on Kubernetes 1.32?" (removed API table)
- "Check this `values.yaml` before I publish the chart."
- "Render the chart in `charts/app` with `values-prod.yaml` and lint the result." (needs `helm` installed)

## Rules

| ID | Severity | Rule |
|----|----------|------|
| K8S1000 | error | YAML or document-structure problem (parse error with line) |
| K8S1001 | warning | container has no resource requests |
| K8S1002 | warning | container has no memory limit (CPU limits are deliberately not required) |
| K8S1003 | warning | image is untagged or uses :latest |
| K8S1004 | info | image is not pinned by digest |
| K8S1005 | error | privileged container |
| K8S1006 | warning / error | allowPrivilegeEscalation is not false (error when explicitly true) |
| K8S1007 | error | container runs as root |
| K8S1008 | warning | runAsNonRoot is not enforced |
| K8S1009 | warning | root filesystem is writable |
| K8S1010 | warning | capabilities are not dropped |
| K8S1011 | error / warning | dangerous capability added (SYS_ADMIN, ALL, ... error; others warning) |
| K8S1012 | error | hostNetwork is enabled |
| K8S1013 | error | hostPID or hostIPC is enabled |
| K8S1014 | warning / error | hostPath volume (error for sensitive locations) |
| K8S1015 | error | container runtime socket (docker.sock, containerd.sock, ...) mounted |
| K8S1016 | warning | no livenessProbe |
| K8S1017 | warning | no readinessProbe |
| K8S1018 | info | single replica |
| K8S1019 | info | replicated workload has no PodDisruptionBudget |
| K8S1020 | warning / info | default namespace (info when metadata.namespace is omitted) |
| K8S1021 | error | secret as a plain env value (name and length only) |
| K8S1022 | warning | secret-looking data in a ConfigMap |
| K8S1023 | warning | Secret with inline data in a manifest |
| K8S1024 | info / warning | service account token is auto-mounted (warning when explicitly true) |
| K8S1025 | info | no pod-level securityContext |
| K8S1026 | warning | no seccomp profile |
| K8S1027 | warning / error | imagePullPolicy problem (invalid value is an error) |
| K8S1028 | warning | Service of type LoadBalancer is exposed |
| K8S1029 | info | Service of type NodePort is exposed |
| K8S1030 | info | namespace has no NetworkPolicy |
| K8S1031 | warning | CronJob concurrencyPolicy allows overlap |
| K8S1032 | info | CronJob history limits not set |
| K8S1033 | error / warning | removed (error) or deprecated (warning) apiVersion, with replacement |
| K8S1034 | warning | hostPort in use |
| K8S1035 | warning | Ingress without TLS |
| K8S1036 | info | bare Pod |
| K8S1037 | info | workload uses the default service account |
| K8S1038 | info | namespace has no Pod Security Admission label |
| K8S1039 | error | duplicate mapping key |
| K8S1040 | warning | Service uses externalIPs |
| K8S2001 | error | selector does not match the pod template labels |
| K8S2002 | warning | Service selector matches no pod template |
| K8S2003 | warning | Ingress backend Service not found |
| K8S2004 | error | Ingress backend port not exposed by the Service |
| K8S2005 | warning | ConfigMap referenced but not defined (info when no ConfigMaps are provided at all) |
| K8S2006 | info | Secret referenced but not defined (Secrets created by ExternalSecret, SealedSecret and cert-manager Certificate are recognised) |
| K8S2007 | warning | PersistentVolumeClaim referenced but not defined |
| K8S2008 | info | ServiceAccount referenced but not defined |
| K8S2009 | error | key not present in the referenced ConfigMap/Secret |
| K8S2010 | warning / error | Service targetPort does not match a container port (named port: error) |
| K8S2011 | warning | HorizontalPodAutoscaler target not found |
| K8S2012 | warning | PodDisruptionBudget selects no workload |
| K8S2013 | error | duplicate resource |
| K8S2014 | warning | StatefulSet serviceName not found |
| K8S2015 | warning | binding refers to a Role that is not defined |
| K8S2016 | error | Service with several ports needs port names |
| K8S2017 | error | volumeMount refers to a volume that is not declared |
| K8S3001 | error | wildcard verbs in a role |
| K8S3002 | error | wildcard resources in a role |
| K8S3003 | error | ClusterRoleBinding to cluster-admin |
| K8S3004 | warning | RoleBinding to cluster-admin |
| K8S3005 | warning | role can read Secrets |
| K8S3006 | error | escalate, bind or impersonate verb |
| K8S3007 | warning | binding to the default ServiceAccount |
| K8S3008 | error | binding to anonymous or unauthenticated users |
| K8S3009 | warning | binding to system:authenticated |
| K8S3010 | warning | role can exec into pods |
| K8S3011 | warning | role can use the nodes/proxy subresource |
| K8S4001 | warning | image tag is latest or missing in values |
| K8S4002 | info | resources are not set in values |
| K8S4003 | error | secret stored in values |
| K8S4004 | info | empty securityContext in values |
| K8S4005 | warning / info | Service exposed publicly by default |
| K8S4006 | info | replicaCount is 1 |
| K8S4007 | warning | insecure security setting in values |

### Removed and deprecated APIs

K8S1033 knows 58 apiVersion/kind pairs (extensions/v1beta1, apps/v1beta1 and v1beta2, networking.k8s.io/v1beta1
Ingress, policy/v1beta1 PodSecurityPolicy and PodDisruptionBudget, batch/v1beta1 CronJob, autoscaling/v2beta1
and v2beta2, rbac v1beta1, admissionregistration, apiextensions, certificates, storage, discovery, events,
node, flowcontrol, and more). A removed API is an error and names the release that dropped it (for example
"batch/v1beta1 CronJob was removed in Kubernetes 1.25"); a still-served deprecated one is a warning. The table
lives in `src/kubelint_mcp/deprecations.py` and is checked against known facts by the tests.

## What it does not do

- It checks the files you give it, not the cluster. References are resolved only inside those files;
  an object missing from them is reported (as info when it plausibly lives elsewhere), not assumed absent.
- It does not validate against the OpenAPI schema (use kubeconform for that); it looks for mistakes that
  schema validation accepts.
- The line of a finding is the YAML line of the offending field, or the nearest enclosing key when the
  field is absent (the container, the pod `spec:`, the `kind:` line).
- Helm templates with `{{ }}` must be rendered first (`helm template`), or use `render_helm`.

## Security

- **Read-only and offline.** Nothing is applied; no network access; no `kubectl`. The only subprocess is
  the opt-in `render_helm` (see below).
- **Sandboxed.** Every path is resolved (symlinks and `..` included) and must stay inside `--dir`.
  Files over 2 MB, directories over 300 files and 20 MB, and non-UTF-8 files are refused with a clear message.
- **Safe YAML.** `yaml.SafeLoader` only, so no tag can construct an object. Alias bombs ("billion laughs") are
  detected by computing the expanded size with memoization and refusing documents above 200,000 nodes;
  nesting is capped; more than 1000 documents per file are ignored with a note.
- **Secrets never leave.** Findings, explanations and diffs show a name and a length (`DB_PASSWORD (12
  characters, value redacted)`), never a value. YAML parse errors are rebuilt without PyYAML's source
  snippet, and diff context lines are filtered, so a secret on a neighbouring line cannot slip out.
- **`render_helm`** runs `helm template <release> <chart> [--namespace ns] [--values file]` as an argument
  list (no shell), with a 60 second timeout and without `KUBECONFIG`. It never passes `--validate` or
  `--dry-run`, so helm cannot reach a cluster. It does nothing unless the call says `allow_exec=true` and a
  `helm` binary exists. Rendering an untrusted chart is still executing someone else's templates: do it only
  when you trust the chart.

## Development

```bash
uv sync --extra test
uv run pytest
uv run ruff check src tests
uv run mypy --strict src
```

Tests run the real code over real files, a real subprocess for `render_helm` (a fake `helm` script, plus
real helm when installed), and launch the installed server over stdio to list and call every tool.

MIT licensed.
