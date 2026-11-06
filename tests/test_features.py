"""Behaviour around the rules: line numbers in multi-document files, parse errors, List/CRD/alias handling,
suppression, the sandbox, caps, and the explain / overview / fix-preview tools."""

from __future__ import annotations

import os
import sys
import time

import pytest

from conftest import DIGEST, build_base, write
from kubelint_mcp import server
from kubelint_mcp.errors import UserError
from kubelint_mcp.files import Sandbox
from kubelint_mcp.model import load_set
from kubelint_mcp.registry import run_rules

POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: p%d
  namespace: n
spec:
  containers:
    - name: c
      image: nginx:latest
"""


def ids(found, rule):
    return sorted(f.line for f in found if f.rule == rule)


@pytest.fixture
def srv(tmp_path):
    server.configure(str(tmp_path), [])
    yield tmp_path
    server.configure(None, [])


# ---------------------------------------------------------------- positions


def test_line_numbers_in_a_multi_document_file(lint_text):
    text = "# comment\n" + "---\n".join(POD % i for i in range(3))
    # doc i starts at line 2 + 9*i (header comment, then 9 lines per doc incl. no separator lines counted twice)
    found = lint_text(text)
    image_lines = [i + 1 for i, ln in enumerate(text.split("\n")) if "image: nginx:latest" in ln]
    assert len(image_lines) == 3
    assert ids(found, "K8S1003") == image_lines


def test_crlf_files_report_the_same_lines(lint_text):
    lf = POD % 1
    crlf = lf.replace("\n", "\r\n")
    assert ids(lint_text(lf), "K8S1003") == ids(lint_text(crlf), "K8S1003") == [9]


def test_utf8_bom_and_unicode_are_fine(lint_text):
    text = "﻿# café\n" + (POD % 1).replace("name: c", "name: café")
    assert ids(lint_text(text), "K8S1003") == [10]


def test_flow_style_and_quoted_values(lint_text):
    text = 'apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: n}\nspec:\n  containers: [{name: c, image: "nginx:latest"}]\n'
    assert ids(lint_text(text), "K8S1003") == [5]


def test_empty_documents_and_comment_only_files_are_quiet(lint_text):
    assert lint_text("---\n---\n# nothing\n---\n") == []
    assert lint_text("") == []


# ---------------------------------------------------------------- parse problems


def test_yaml_error_is_a_finding_with_a_line_not_a_crash(lint_text):
    text = (POD % 1) + "---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: [oops\n  namespace: n\nspec: {}\n"
    found = lint_text(text)
    parse = [f for f in found if f.rule == "K8S1000"]
    assert len(parse) == 1 and parse[0].severity == "error"
    assert 13 <= parse[0].line <= 15
    assert "YAML parse error" in parse[0].message
    # the valid first document was still linted
    assert ids(found, "K8S1003") == [9]


def test_parse_error_message_never_echoes_the_source_line(lint_text):
    secret = "ZZ-FAKE-SECRET-9f8e7d"
    text = f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\nstringData:\n  password: {secret}\n  bad: [x\n  other: {secret}\n"
    found = lint_text(text)
    blob = " ".join(f.message + f.fix for f in found)
    assert any(f.rule == "K8S1000" for f in found)
    assert secret not in blob


def test_bad_file_does_not_stop_the_other_files(load):
    rs = load({"good.yaml": POD % 1, "bad.yaml": "a: [\n", "other/ok.yml": POD % 2})
    found = run_rules(rs, "K8S1", frozenset())
    assert {f.file for f in found if f.rule == "K8S1000"} == {"bad.yaml"}
    assert {f.file for f in found if f.rule == "K8S1003"} == {"good.yaml", "other/ok.yml"}


def test_non_mapping_document_and_missing_kind(lint_text):
    found = lint_text("- a\n- b\n---\nfoo: bar\n")
    msgs = [(f.rule, f.line) for f in found if f.rule == "K8S1000"]
    assert msgs == [("K8S1000", 1), ("K8S1000", 4)]


def test_directory_mode_skips_non_kubernetes_yaml_silently(load):
    rs = load({"Chart.yaml": "name: demo\nversion: 0.1.0\n", "values.yaml": "replicaCount: 1\n", "pod.yaml": POD % 1})
    found = run_rules(rs, "K8S1", frozenset())
    assert not [f for f in found if f.rule == "K8S1000"]
    assert "2 YAML document(s) without apiVersion/kind were skipped" in rs.lint_note


def test_unrendered_helm_templates_are_skipped_with_a_hint_in_directory_mode(load):
    tpl = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n  labels: {{- include \"x.labels\" . | nindent 4 }}\n"
    rs = load({"templates/deploy.yaml": tpl, "pod.yaml": POD % 1})
    assert rs.helm_templates == 1
    assert "helm template" in rs.lint_note
    assert not [f for f in run_rules(rs, "K8S1", frozenset()) if f.rule == "K8S1000"]


def test_unrendered_helm_template_as_a_single_file_is_an_error_with_hint(lint_text):
    tpl = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n"
    found = lint_text(tpl)
    assert found and found[0].rule == "K8S1000" and "helm template" in found[0].fix


def test_helm_template_output_with_source_comments_lints(lint_text):
    text = "---\n# Source: demo/templates/svc.yaml\n" + "apiVersion: v1\nkind: Service\nmetadata:\n  name: demo\n  namespace: n\nspec:\n  type: LoadBalancer\n  ports:\n    - port: 80\n"
    assert ids(lint_text(text), "K8S1028") == [9]


def test_deeply_nested_yaml_is_a_finding_not_a_crash(lint_text):
    text = "a: " + "[" * 3000 + "]" * 3000 + "\n"
    found = lint_text(text)
    assert [f.rule for f in found] == ["K8S1000"]
    assert "nested" in found[0].message or "nesting" in found[0].message


def test_duplicate_keys_in_a_mapping_are_reported(lint_text):
    text = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n  name: b\nspec:\n  containers: []\n"
    assert ids(lint_text(text), "K8S1039") == [5]


# ---------------------------------------------------------------- List, CRD, anchors


def test_list_kind_items_get_their_own_lines(lint_text):
    text = "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: Pod\n    metadata: {name: a, namespace: n}\n    spec:\n      containers:\n        - name: c\n          image: nginx:latest\n"
    found = lint_text(text)
    assert ids(found, "K8S1003") == [10]
    assert all(f.resource == "Pod/a" for f in found if f.rule == "K8S1003")


def test_custom_resources_are_skipped_quietly_with_a_count(load):
    crd = "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata:\n  name: c\n  namespace: n\nspec:\n  secretName: x\n"
    rs = load({"a.yaml": crd + "---\n" + crd.replace("name: c", "name: d") + "---\n" + POD % 1})
    found = run_rules(rs, "K8S1", frozenset())
    assert not [f for f in found if "Certificate" in f.resource]
    assert rs.unknown_kinds["Certificate"] == 2
    assert "2 object(s) of kinds with no lint rules were skipped quietly" in rs.lint_note and "Certificate x2" in rs.lint_note


def test_deprecated_custom_group_apiversion_is_still_checked(lint_text):
    found = lint_text("apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinition\nmetadata:\n  name: x.example.com\n")
    assert ids(found, "K8S1033") == [1]


def test_anchors_aliases_and_merge_keys(lint_text):
    text = """\
x-container: &base
  name: app
  image: nginx:latest
  securityContext: &sc
    privileged: true
apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: n
spec:
  containers:
    - <<: *base
      name: one
    - *base
"""
    found = lint_text(text)
    # container 'one' overrides the name via merge; both containers inherit the image and privileged flag
    assert {f.rule for f in found} >= {"K8S1003", "K8S1005"}
    assert {f.resource for f in found if f.rule == "K8S1005"} == {"Pod/p"}
    assert all(f.line > 0 for f in found)


# ---------------------------------------------------------------- suppression and disabling


def test_ignore_comment_above_a_container_covers_the_container(lint_text):
    text = POD % 1
    text = text.replace("    - name: c\n", "    # kubelint-ignore: K8S1003, K8S1001\n    - name: c\n")
    found = lint_text(text)
    assert ids(found, "K8S1003") == [] and ids(found, "K8S1001") == []
    assert ids(found, "K8S1002") != []  # other rules still fire


def test_ignore_trailing_comment_covers_only_its_line(lint_text):
    text = (POD % 1).replace("image: nginx:latest", "image: nginx:latest # kubelint-ignore: K8S1003")
    found = lint_text(text)
    assert ids(found, "K8S1003") == [] and ids(found, "K8S1001") != []


def test_ignore_at_top_of_a_document_covers_the_whole_document(lint_text):
    text = "# kubelint-ignore: K8S1003\n" + (POD % 1) + "---\n" + (POD % 2)
    found = lint_text(text)
    assert ids(found, "K8S1003") == [20]  # only the second document


def test_ignore_comment_for_a_different_rule_does_nothing(lint_text):
    text = (POD % 1).replace("    - name: c\n", "    # kubelint-ignore: K8S1004\n    - name: c\n")
    assert ids(lint_text(text), "K8S1003") == [10]


def test_disable_flag_removes_rules(lint_text):
    found = lint_text(POD % 1, disabled=frozenset({"K8S1003", "K8S1000"}))
    assert not any(f.rule == "K8S1003" for f in found) and any(f.rule == "K8S1001" for f in found)


def test_configure_rejects_unknown_rule_ids(tmp_path):
    with pytest.raises(UserError, match="unknown rule id"):
        server.configure(str(tmp_path), ["K8S9999"])
    server.configure(str(tmp_path), ["K8S4003", "K8S3001", "K8S2001", "K8S1000"])  # every family is accepted
    server.configure(None, [])


def test_every_rule_has_id_title_and_fixed_prefix():
    from kubelint_mcp.registry import RULES

    assert len(RULES) >= 50
    for rid, info in RULES.items():
        assert rid.startswith("K8S") and len(rid) == 7 and info.title and info.severity in ("error", "warning", "info")


# ---------------------------------------------------------------- sandbox and caps


def test_paths_outside_dir_are_refused_with_a_clear_message(srv):
    outside = srv.parent / "outside_kubelint.yaml"
    write(str(outside), POD % 1)
    try:
        for p in (str(outside), "../outside_kubelint.yaml"):
            with pytest.raises(UserError, match="outside the directory this server is allowed to read"):
                server.lint_manifests(p)
    finally:
        outside.unlink()


def test_symlink_pointing_outside_is_refused(srv):
    outside = srv.parent / "target_kubelint.yaml"
    write(str(outside), POD % 1)
    link = srv / "link.yaml"
    try:
        os.symlink(str(outside), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this machine (Windows without developer mode)")
    try:
        with pytest.raises(UserError, match="outside the directory"):
            server.lint_manifests("link.yaml")
        write(str(srv / "ok.yaml"), POD % 2)
        # directory mode silently ignores the escaping link and still lints the rest
        assert "ok.yaml" in server.lint_manifests(".")
    finally:
        outside.unlink()


def test_missing_file_and_directory_without_yaml(srv):
    with pytest.raises(UserError, match="Not found"):
        server.lint_manifests("nope.yaml")
    (srv / "empty").mkdir()
    with pytest.raises(UserError, match="No .yaml/.yml files"):
        server.lint_manifests("empty")


def test_hundred_thousand_character_path_is_a_user_error(srv):
    for p in ("a" * 100_000, ("sub/" * 25_000) + "x.yaml"):
        with pytest.raises(UserError):
            server.lint_manifests(p)


def test_nul_byte_and_empty_path(srv):
    for p in ("", "a\x00b.yaml"):
        with pytest.raises(UserError):
            server.lint_manifests(p)


def test_oversized_file_is_refused(srv):
    write(str(srv / "big.yaml"), "# " + "x" * 2_100_000 + "\n")
    with pytest.raises(UserError, match="limit"):
        server.lint_manifests("big.yaml")


def test_non_utf8_file_is_refused(srv):
    with open(srv / "bin.yaml", "wb") as fh:
        fh.write(b"\xff\xfe\x00\x00 not text \x80")
    with pytest.raises(UserError, match="not valid UTF-8"):
        server.lint_manifests("bin.yaml")


def test_huge_multidocument_file_is_capped(srv):
    docs = "".join(f"---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c{i}\n  namespace: n\n" for i in range(1200))
    write(str(srv / "many.yaml"), docs)
    out = server.lint_manifests("many.yaml")
    assert "more than 1000 documents" in out
    assert "1000 object(s)" in out


def test_file_count_cap_in_directory_mode(srv):
    for i in range(310):
        write(str(srv / f"f{i:03}.yaml"), POD % i)
    out = server.k8s_overview(".")
    assert "300 file(s)" in out and "only the first 300" in out


def test_absolute_windows_style_and_forward_slash_paths_work(srv):
    write(str(srv / "sub" / "pod.yaml"), POD % 1)
    for p in (str(srv / "sub" / "pod.yaml"), "sub/pod.yaml", os.path.join("sub", "pod.yaml")):
        assert "K8S1003" in server.lint_manifests(p)
    if sys.platform == "win32":
        assert "K8S1003" in server.lint_manifests("sub\\pod.yaml")
        assert "K8S1003" in server.lint_manifests(str(srv / "sub" / "pod.yaml").replace("\\", "/"))


def test_regex_heavy_inputs_stay_fast(lint_text):
    nasty = "a:" * 40_000
    text = (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  namespace: n\nspec:\n  containers:\n    - name: c\n"
        f"      image: '{'registry/' * 5000}x:1'\n      env:\n        - name: TOKEN_{'A_' * 5000}X\n          value: '{nasty}'\n"
        f"        - name: URL\n          value: 'http://{'u:' * 30000}'\n        - name: BLOB\n          value: '{'-----BEGIN ' * 20000}'\n"
    )
    t0 = time.perf_counter()
    found = lint_text(text)
    assert time.perf_counter() - t0 < 10
    assert any(f.rule == "K8S1021" for f in found)


# ---------------------------------------------------------------- secrets never leak


FAKE = ["hunter2-FAKE-pw", "ghp_" + "Z" * 36, "AKIAFAKEFAKEFAKE1234", "s3cr3t-FAKE-token-value"]


def secret_manifest() -> str:
    return (
        build_base(
            edits=(
                (
                    f"          image: registry.example.com/shop/web:1.4.2@{DIGEST}\n",
                    f"          image: registry.example.com/shop/web:1.4.2@{DIGEST}\n          env:\n"
                    f"            - name: DB_PASSWORD\n              value: {FAKE[0]}\n"
                    f"            - name: GH\n              value: {FAKE[1]}\n"
                    f"            - name: AWS_KEY\n              value: {FAKE[2]}\n",
                ),
            ),
            extra=(f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: shop\nstringData:\n  api_token: {FAKE[3]}\n"
                   f"---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  namespace: shop\ndata:\n  secret_key: {FAKE[3]}\n",),
        )
    )


def test_planted_secrets_never_appear_in_any_tool_output(srv):
    write(str(srv / "app.yaml"), secret_manifest())
    outputs = [
        server.k8s_overview("app.yaml"),
        server.lint_manifests("app.yaml"),
        server.check_references("app.yaml"),
        server.rbac_review("app.yaml"),
        server.suggest_fixes("app.yaml"),
        server.explain_resource("app.yaml", "Deployment", "web"),
        server.explain_resource("app.yaml", "Secret", "s"),
        server.explain_resource("app.yaml", "ConfigMap", "c"),
    ]
    blob = "\n".join(outputs)
    for s in FAKE:
        assert s not in blob, s
    assert "K8S1021" in blob and "DB_PASSWORD" in blob and "characters, value redacted" in blob


# ---------------------------------------------------------------- explain, overview, fixes


def test_explain_deployment_in_plain_english(srv):
    write(str(srv / "app.yaml"), build_base())
    out = server.explain_resource("app.yaml", "deployment", "web", "shop")
    assert "keeps 2 replica(s)" in out
    assert "non-root enforced" in out and "read-only root filesystem" in out and "all capabilities dropped" in out
    assert "ServiceAccount 'web' (defined in app.yaml" in out
    assert "Service 'web' (ClusterIP)" in out and "PodDisruptionBudget 'web'" in out and "NetworkPolicy 'default-deny'" in out
    assert "Lint findings for this object: 0" in out


def test_explain_bad_deployment_shows_the_risks(srv):
    text = build_base(edits=(("      automountServiceAccountToken: false\n", "      hostNetwork: true\n"), ("readOnlyRootFilesystem: true", "privileged: true")))
    write(str(srv / "app.yaml"), text)
    out = server.explain_resource("app.yaml", "Deployment", "web")
    assert "PRIVILEGED" in out and "hostNetwork" in out and "K8S1005" in out


def test_explain_other_kinds(srv):
    write(str(srv / "app.yaml"), build_base() + "---\napiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata: {name: r, namespace: shop}\nrules:\n  - apiGroups: ['']\n    resources: [pods]\n    verbs: [get, list]\n")
    assert "gives a stable address" in server.explain_resource("app.yaml", "Service", "web")
    assert "may get, list on pods" in server.explain_resource("app.yaml", "Role", "r")
    assert "an identity for pods" in server.explain_resource("app.yaml", "ServiceAccount", "web")
    assert "limits voluntary evictions" in server.explain_resource("app.yaml", "PodDisruptionBudget", "web")


def test_explain_unknown_object_lists_what_exists(srv):
    write(str(srv / "app.yaml"), build_base())
    with pytest.raises(UserError, match="Deployment objects found: web"):
        server.explain_resource("app.yaml", "Deployment", "nope")
    with pytest.raises(UserError, match="Kinds present"):
        server.explain_resource("app.yaml", "Gizmo", "x")


def test_explain_needs_a_namespace_when_ambiguous(srv):
    two = build_base() + "---\n" + BASE_COPY_OTHER_NS()
    write(str(srv / "app.yaml"), two)
    with pytest.raises(UserError, match="defined 2 times"):
        server.explain_resource("app.yaml", "Deployment", "web")
    assert "namespace other" in server.explain_resource("app.yaml", "Deployment", "web", "other")


def BASE_COPY_OTHER_NS() -> str:
    from conftest import BASE_DOCS

    return BASE_DOCS["deployment"].replace("namespace: shop", "namespace: other")


def test_overview_summarizes_everything(srv):
    write(str(srv / "app.yaml"), build_base())
    out = server.k8s_overview("app.yaml")
    assert "6 object(s) in 1 file(s)" in out
    assert "Deployment x1" in out and "shop (5)" in out and "(cluster-scoped) (1): Namespace/shop" in out
    assert "replicas=2" in out and "app [registry.example.com/shop/web:1.4.2@" in out
    assert "Service/web" in out and "-> Deployment/web" in out


def test_overview_lists_ingress_routes(srv):
    ing = "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: {name: i, namespace: shop}\nspec:\n  rules:\n    - host: a.example.com\n      http:\n        paths:\n          - path: /api\n            pathType: Prefix\n            backend:\n              service: {name: web, port: {number: 80}}\n"
    write(str(srv / "app.yaml"), build_base(extra=(ing,)))
    assert "a.example.com/api -> web:80" in server.k8s_overview("app.yaml") and "no TLS" in server.k8s_overview("app.yaml")


def test_suggest_fixes_diff_and_relint(srv):
    bad = (
        "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: j, namespace: n}\nspec:\n  schedule: '* * * * *'\n  jobTemplate:\n    spec:\n      template:\n        spec:\n"
        "          hostNetwork: true\n          containers:\n            - name: c\n              image: busybox:1.36\n              securityContext:\n                privileged: true\n"
        "            - name: d\n              image: busybox:1.36\n              securityContext:\n                runAsUser: 5\n"
        "            - name: e\n              image: busybox:1.36\n"
    )
    write(str(srv / "j.yaml"), bad)
    out = server.suggest_fixes("j.yaml")
    assert "nothing was written" in out
    assert "-apiVersion: batch/v1beta1\n+apiVersion: batch/v1" in out
    assert "-          hostNetwork: true\n+          hostNetwork: false" in out
    assert "-                privileged: true\n" in out and "+                privileged: false" in out
    assert "+                allowPrivilegeEscalation: false" in out
    assert "+              securityContext:\n+                allowPrivilegeEscalation: false" in out
    assert "findings resolved: " in out and "K8S1033 x1" in out and "K8S1012 x1" in out and "K8S1005 x1" in out
    assert open(srv / "j.yaml", encoding="utf-8", newline="").read() == bad  # never written


def test_suggest_fixes_patched_text_is_valid_and_clean_of_fixed_rules(srv):
    from kubelint_mcp.fixes import FIXABLE, _collect, apply_edits
    from kubelint_mcp.model import build_set

    text = build_base(edits=(("            allowPrivilegeEscalation: false\n", "            privileged: true\n"),))
    rs = build_set([("a.yaml", text)], False)
    edits, manual = _collect(rs, text.split("\n"), frozenset())
    assert edits
    patched = apply_edits(text, edits)
    rs2 = build_set([("a.yaml", patched)], False)
    assert not rs2.load_hits
    after = {f.rule for f in run_rules(rs2, "K8S1", frozenset())}
    assert "K8S1005" not in after and "K8S1006" not in after
    assert FIXABLE


def test_suggest_fixes_keeps_crlf_and_respects_ignore_comments(srv):
    text = ("apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: n}\nspec:\n  # kubelint-ignore: K8S1012\n  hostNetwork: true\n  hostPID: true\n  containers:\n    - name: c\n      image: busybox:1.36\n").replace("\n", "\r\n")
    write(str(srv / "p.yaml"), text)
    out = server.suggest_fixes("p.yaml")
    assert "hostPID: true" in out and "+  hostPID: false" in out
    assert "+  hostNetwork" not in out
    assert "CRLF" in out


def test_suggest_fixes_hides_values_next_to_edits(srv):
    text = ("apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: n}\nspec:\n  containers:\n    - name: c\n      image: busybox:1.36\n      securityContext:\n"
            "        privileged: true\n      env:\n        - name: X\n          value: FAKE-CONTEXT-VALUE-123\n")
    write(str(srv / "p.yaml"), text)
    out = server.suggest_fixes("p.yaml")
    assert "privileged: false" in out and "FAKE-CONTEXT-VALUE-123" not in out


def test_suggest_fixes_rejects_a_directory(srv):
    (srv / "d").mkdir()
    with pytest.raises(UserError):
        server.suggest_fixes("d")


def test_suggest_fixes_with_nothing_to_fix(srv):
    write(str(srv / "app.yaml"), build_base())
    assert "no safe automatic fixes apply" in server.suggest_fixes("app.yaml")


def test_directory_lint_reports_relative_posix_paths(srv):
    write(str(srv / "a" / "b" / "pod.yaml"), POD % 1)
    out = server.lint_manifests(".")
    assert "a/b/pod.yaml:9" in out and "\\" not in out.split("pod.yaml")[0].splitlines()[-1]


def test_load_set_on_missing_namespace_in_file_mode(tmp_path):
    write(str(tmp_path / "p.yaml"), POD % 1)
    rs = load_set(Sandbox(str(tmp_path)), "p.yaml")
    assert len(rs.resources) == 1


def test_thousands_of_ignore_comments_stay_linear(lint_text):
    body = "".join(f"    # kubelint-ignore: K8S1003\n    - name: c{i}\n      image: nginx:latest\n" for i in range(8000))
    text = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: n}\nspec:\n  containers:\n" + body
    t0 = time.perf_counter()
    lint_text(text)
    assert time.perf_counter() - t0 < 20
    stuffed = "# kubelint-ignore: K8S1001\n" * 60_000 + "a: b\n"
    t0 = time.perf_counter()
    lint_text(stuffed)
    assert time.perf_counter() - t0 < 20
