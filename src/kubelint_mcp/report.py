"""Text formatting shared by all tools."""

from __future__ import annotations

from .findings import Finding

MAX_OUTPUT = 60_000
MAX_SHOWN = 300

IGNORE_HINT = (
    "Suppress one finding with a `# kubelint-ignore: <RULE-ID>` comment on the line above it "
    "(above a container item or a field to cover everything under it)."
)


def clip(text: str, limit: int = MAX_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [{len(text) - limit} more characters truncated]"


def counts(findings: list[Finding]) -> dict[str, int]:
    c = {"error": 0, "warning": 0, "info": 0}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


def format_findings(label: str, findings: list[Finding], note: str = "") -> str:
    c = counts(findings)
    head = f"{label}: {len(findings)} finding(s) ({c['error']} error, {c['warning']} warning, {c['info']} info)"
    if not findings:
        return head + ". Nothing to fix." + (f"\n{note}" if note else "")
    lines = [head, ""]
    for f in findings[:MAX_SHOWN]:
        lines.append(f"[{f.rule}] {f.severity} {f.file}:{f.line} ({f.resource}): {f.message}")
        lines.append(f"    fix: {f.fix}")
    if len(findings) > MAX_SHOWN:
        lines.append(f"... and {len(findings) - MAX_SHOWN} more finding(s) not shown (fix the errors first, or --disable noisy rule ids).")
    if note:
        lines += ["", note]
    lines += ["", IGNORE_HINT]
    return clip("\n".join(lines))
