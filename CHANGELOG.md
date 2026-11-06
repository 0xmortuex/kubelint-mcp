# Changelog

## 0.1.0

First release.

- Eight tools: `k8s_overview`, `lint_manifests`, `check_references`, `rbac_review`, `explain_resource`,
  `suggest_fixes`, `values_review`, `render_helm` (opt-in, needs a local `helm`).
- Rule families: K8S1xxx manifest hygiene and security, K8S2xxx cross-resource references,
  K8S3xxx RBAC, K8S4xxx Helm values.
- Embedded table of removed and deprecated Kubernetes API versions with replacements.
- Position-tracking YAML loader (line numbers for every finding), alias-bomb guard, `List` expansion.
- `# kubelint-ignore:` comments and `--disable` flag; `--dir` sandbox.
- Secret values are never echoed: names and lengths only.
