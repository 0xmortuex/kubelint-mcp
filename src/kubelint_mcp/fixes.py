"""suggest_fixes: a unified diff of the safe, mechanical fixes. Never writes anything.

Safe means: flipping an insecure boolean to its secure value, adding allowPrivilegeEscalation: false, and
renaming an apiVersion where the schema did not change. Everything else is listed for a human.
Each edit is a one-line replacement or an insertion computed from the recorded YAML positions; after applying
all edits in memory the result is re-parsed and re-linted to confirm it is still valid YAML and the fixed
findings are gone.
"""

from __future__ import annotations

import difflib
import re
from collections import Counter
from dataclasses import dataclass

from . import deprecations
from .errors import UserError
from .findings import Finding
from .ignores import IgnoreRange
from .model import Container, Resource, ResourceSet, as_dict, build_set, pod_view
from .registry import run_rules
from .report import clip
from .yamlpos import Path

FIXABLE = ("K8S1005", "K8S1006", "K8S1012", "K8S1013", "K8S1033")

_SAFE_CONTEXT_KEYS = {
    "apiversion", "kind", "metadata", "name", "namespace", "spec", "image", "imagepullpolicy", "containers",
    "initcontainers", "securitycontext", "privileged", "allowprivilegeescalation", "hostnetwork", "hostpid",
    "hostipc", "replicas", "template", "labels", "selector", "matchlabels", "ports", "containerport", "protocol",
    "resources", "limits", "requests", "cpu", "memory", "runasnonroot", "runasuser", "readonlyrootfilesystem",
    "capabilities", "drop", "add", "volumes", "volumemounts", "mountpath", "app", "schedule", "jobtemplate",
    "serviceaccountname", "restartpolicy", "strategy", "type", "livenessprobe", "readinessprobe", "startupprobe",
    "serviceaccount", "automountserviceaccounttoken", "seccompprofile", "fsgroup", "concurrencypolicy",
}
_KV = re.compile(r"^(\s*(?:-\s+)?)([A-Za-z0-9_.\-/]+)(\s*:)(\s*)(.*)$")


@dataclass
class Edit:
    line: int  # 1-based
    kind: str  # "replace" or "insert" (insert goes AFTER `line`)
    text: list[str]
    rule: str
    why: str


def _active(rule: str, line: int, disabled: frozenset[str], ignores: list[IgnoreRange]) -> bool:
    return rule not in disabled and not any(r.covers(rule, line) for r in ignores)


def _flip(res: Resource, text_lines: list[str], path: Path, rule: str, why: str, edits: list[Edit]) -> bool:
    p = res.doc.position(res.base + path)
    if p is None:
        return False
    src = text_lines[p.line - 1]
    new, n = re.subn(r"(\b" + re.escape(str(path[-1])) + r"\s*:\s*)(true|True|TRUE)\b", r"\1false", src, count=1)
    if n != 1:
        return False
    edits.append(Edit(p.line, "replace", [new], rule, why))
    return True


def _insert_escalation(res: Resource, c: Container, edits: list[Edit], rule: str) -> bool:
    doc = res.doc
    cpath = res.base + c.path
    if cpath in doc.flow:
        return False
    sc = c.data.get("securityContext")
    why = f"container '{c.name}': add allowPrivilegeEscalation: false"
    if isinstance(sc, dict) and sc:
        scpath = cpath + ("securityContext",)
        if scpath in doc.flow:
            return False
        kids = [(doc.pos[scpath + (k,)], k) for k in sc if (scpath + (k,)) in doc.pos]
        sp = doc.pos.get(scpath)
        if not kids or sp is None:
            return False
        first = min(kids, key=lambda t: (t[0].line, t[0].col))[0]
        if first.line <= sp.line:
            return False  # value shares the key's line, e.g. "securityContext: {…}"
        edits.append(Edit(sp.line, "insert", [" " * first.col + "allowPrivilegeEscalation: false"], rule, why))
        return True
    if "securityContext" in c.data:
        return False
    positions = [(doc.pos[cpath + (k,)], k) for k in c.data if (cpath + (k,)) in doc.pos]
    if not positions:
        return False
    first_pos, key = min(positions, key=lambda t: (t[0].line, t[0].col))
    if first_pos.end_line != first_pos.line or isinstance(c.data[key], (dict, list)):
        return False
    pad = " " * first_pos.col
    edits.append(Edit(first_pos.line, "insert", [pad + "securityContext:", pad + "  allowPrivilegeEscalation: false"], rule, why))
    return True


def _collect(rs: ResourceSet, text_lines: list[str], disabled: frozenset[str]) -> tuple[list[Edit], list[str]]:
    edits: list[Edit] = []
    manual: list[str] = []
    for res in rs.resources:
        ign = res.file.ignores
        d = deprecations.lookup(res.api, res.kind)
        if d is not None and d.removed:
            safe = d.safe_rename or (d.replacement == "apps/v1" and res.get("spec", "selector") is not None)
            line = res.line("apiVersion")
            if safe and _active("K8S1033", line, disabled, ign):
                src = text_lines[line - 1]
                new, n = re.subn(r"(apiVersion\s*:\s*[\"']?)" + re.escape(res.api) + r"([\"']?)", r"\g<1>" + d.replacement + r"\2", src, count=1)
                if n == 1:
                    edits.append(Edit(line, "replace", [new], "K8S1033", f"{res.label}: apiVersion {res.api} -> {d.replacement}"))
        pv = pod_view(res)
        if pv is None:
            continue
        for key, rule in (("hostNetwork", "K8S1012"), ("hostPID", "K8S1013"), ("hostIPC", "K8S1013")):
            if pv.spec.get(key) is True and _active(rule, res.line(*(pv.path + (key,))), disabled, ign):
                _flip(res, text_lines, pv.path + (key,), rule, f"{res.label}: {key} true -> false", edits)
        for c in pv.containers():
            sc = as_dict(c.data.get("securityContext"))
            p_path = c.path + ("securityContext", "privileged")
            unprivileged = False
            if sc.get("privileged") is True and _active("K8S1005", res.line(*p_path), disabled, ign):
                unprivileged = _flip(res, text_lines, p_path, "K8S1005", f"{res.label}: container '{c.name}' privileged true -> false", edits)
            a_path = c.path + ("securityContext", "allowPrivilegeEscalation")
            val = sc.get("allowPrivilegeEscalation")
            if val is True and _active("K8S1006", res.line(*a_path), disabled, ign):
                if not _flip(res, text_lines, a_path, "K8S1006", f"{res.label}: container '{c.name}' allowPrivilegeEscalation true -> false", edits):
                    manual.append(f"{res.label}: container '{c.name}' - set allowPrivilegeEscalation: false by hand (inline form)")
            elif val is None and (sc.get("privileged") is not True or unprivileged) and _active("K8S1006", res.line(*c.path), disabled, ign):
                if not _insert_escalation(res, c, edits, "K8S1006"):
                    manual.append(f"{res.label}: container '{c.name}' - add securityContext.allowPrivilegeEscalation: false by hand (inline YAML form)")
    return edits, manual


def apply_edits(text: str, edits: list[Edit]) -> str:
    """Apply replacements and insertions to the text; the CR of CRLF files stays attached to its line."""
    cr = "\r\n" in text
    lines = text.split("\n")
    for e in sorted(edits, key=lambda x: (x.line, 0 if x.kind == "replace" else 1), reverse=True):
        idx = e.line - 1
        if e.kind == "replace":
            lines[idx] = e.text[0] + ("\r" if cr and lines[idx].endswith("\r") else "")
        else:
            lines[idx + 1 : idx + 1] = [t + ("\r" if cr else "") for t in e.text]
    return "\n".join(lines)


def _safe_context(line: str) -> str:
    """Context lines in the diff come from the user's file; keep structure, hide anything that could be a value."""
    if not line.strip() or line.lstrip().startswith(("#", "---")):
        return line if not line.lstrip().startswith("#") else re.sub(r"#.*", "# <comment>", line)
    m = _KV.match(line)
    if m is None:
        return re.sub(r"\S.*", "<line hidden>", line, count=1)
    head, key, colon, gap, value = m.groups()
    if key.lower() in _SAFE_CONTEXT_KEYS or not value.strip():
        return head + key + colon + gap + re.sub(r"\s+#.*$", "", value)
    return head + key + colon + gap + "<hidden>"


def suggest(rs: ResourceSet, text: str, display: str, disabled: frozenset[str]) -> str:
    text_lines = text.split("\n")
    text_lines = [ln[:-1] if ln.endswith("\r") else ln for ln in text_lines]
    edits, manual = _collect(rs, text_lines, disabled)
    before = run_rules(rs, "K8S1", disabled)
    if not edits:
        out = [f"{display}: no safe automatic fixes apply."]
    else:
        new_text = apply_edits(text, edits)
        rs2 = build_set([(display, new_text)], False)
        if rs2.load_hits and not rs.load_hits:
            raise UserError("Internal error: the proposed edits would produce invalid YAML, so no diff is shown. Please report this file.")
        after = run_rules(rs2, "K8S1", disabled)
        fixed = Counter(f.rule for f in before) - Counter(f.rule for f in after)
        old_lines = text.replace("\r\n", "\n").split("\n")
        new_lines = new_text.replace("\r\n", "\n").split("\n")
        raw = list(difflib.unified_diff(old_lines, new_lines, f"a/{display}", f"b/{display}", n=1, lineterm=""))
        # Every body line passes through _safe_context so a value next to an edit can never leak.
        diff = [ln if i < 2 or ln.startswith("@@") else ln[:1] + _safe_context(ln[1:]) for i, ln in enumerate(raw)]
        out = [f"{display}: {len(edits)} safe edit(s) proposed (nothing was written).", ""]
        out += [f"  - {e.rule}: {e.why}" for e in sorted(edits, key=lambda e: e.line)]
        out += ["", "```diff"] + diff + ["```", ""]
        gone = ", ".join(f"{r} x{n}" for r, n in sorted(fixed.items())) or "none"
        out.append(f"Re-linting the patched text: still valid YAML; findings resolved: {gone}.")
        if "\r\n" in text:
            out.append("The file uses CRLF line endings; the diff is shown with LF. Apply with `git apply --ignore-whitespace`.")
        out.append("Review before applying: privileged: false and allowPrivilegeEscalation: false can break workloads that really need them.")
    remaining: list[Finding] = [f for f in before if f.rule not in FIXABLE]
    if manual:
        out += ["", "Needs a manual change:"] + [f"  - {m}" for m in manual]
    if remaining:
        out += ["", "Other findings need a human decision (run lint_manifests for the fix text): "
                + ", ".join(f"{r} x{n}" for r, n in sorted(Counter(f.rule for f in remaining).items()))]
    return clip("\n".join(out))
