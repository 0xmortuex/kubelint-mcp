"""`# kubelint-ignore: K8S1004, K8S1009` comments.

Scope of a comment:
* trailing a line: that line only;
* on its own line: the next code line and everything nested under it (a container item, a field with
  children); when the next code line is the first line of a document (or a `---` separator), the whole document.

The scan is linear in the file with hard budgets, so a file stuffed with ignore comments cannot make it quadratic.
A comment that would exceed the budget is simply not honoured (findings stay visible: the safe direction).
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

_IGNORE = re.compile(r"#\s*kubelint-ignore:\s*([A-Za-z0-9_,\s]{1,400})")
_ID = re.compile(r"K8S\d{4}", re.IGNORECASE)
MAX_COMMENTS = 5000
SCAN_BUDGET = 2_000_000


@dataclass(frozen=True)
class IgnoreRange:
    start: int
    end: int
    ids: frozenset[str]

    def covers(self, rule: str, line: int) -> bool:
        return self.start <= line <= self.end and rule in self.ids


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_code(line: str) -> bool:
    s = line.strip()
    return bool(s) and not s.startswith("#")


def _is_separator(line: str) -> bool:
    return line.startswith("---") or line.startswith("...")


def compute_ignores(text: str) -> list[IgnoreRange]:
    if "kubelint-ignore" not in text:
        return []
    lines = text.splitlines()
    n = len(lines)
    code = [_is_code(ln) for ln in lines]
    # next_code[i]: first code line index >= i; prev_code[i]: last code line index < i (-1 when none)
    next_code = [n] * (n + 1)
    for i in range(n - 1, -1, -1):
        next_code[i] = i if code[i] else next_code[i + 1]
    prev_code = [-1] * (n + 1)
    last = -1
    for i in range(n):
        prev_code[i] = last
        if code[i]:
            last = i
    out: list[IgnoreRange] = []
    budget = SCAN_BUDGET
    for i, line in enumerate(lines):
        if len(out) >= MAX_COMMENTS or budget <= 0:
            break
        if "kubelint-ignore" not in line:
            continue
        m = _IGNORE.search(line)
        if not m:
            continue
        ids = frozenset(x.upper() for x in _ID.findall(m.group(1)))
        if not ids:
            continue
        if line.lstrip().startswith("#"):
            j = next_code[i + 1]
            if j >= n:
                continue
            end, used = _block_end(lines, code, prev_code, j, budget)
            budget -= used
            if end >= 0:
                out.append(IgnoreRange(j + 1, end + 1, ids))
        else:
            out.append(IgnoreRange(i + 1, i + 1, ids))
    return out


def _block_end(lines: list[str], code: list[bool], prev_code: list[int], start: int, budget: int) -> tuple[int, int]:
    """(index of the last line of the block that begins at lines[start], or -1 when over budget; steps used)."""
    first = lines[start]
    steps = 0
    if _is_separator(first):
        end = start
        for k in range(start + 1, len(lines)):
            steps += 1
            if steps > budget:
                return -1, steps
            if _is_separator(lines[k]):
                break
            end = k
        return end, steps
    base = _indent(first)
    is_item = first.lstrip().startswith("- ") or first.strip() == "-"
    p = prev_code[start]
    first_of_doc = p < 0 or _is_separator(lines[p])
    end = start
    for k in range(start + 1, len(lines)):
        steps += 1
        if steps > budget:
            return -1, steps
        ln = lines[k]
        if base == 0 and first_of_doc:
            if _is_separator(ln):
                break
            end = k
            continue
        if not code[k]:
            continue
        ind = _indent(ln)
        if ind > base or (not is_item and ind == base and ln.lstrip().startswith("- ")):
            end = k
            continue
        break
    return end, steps


class IgnoreIndex:
    """Answers "is this rule ignored on this line?" in O(log n) however many ranges there are."""

    def __init__(self, ranges: list[IgnoreRange]) -> None:
        by_rule: dict[str, list[tuple[int, int]]] = {}
        for r in ranges:
            for rid in r.ids:
                by_rule.setdefault(rid, []).append((r.start, r.end))
        self._starts: dict[str, list[int]] = {}
        self._max_end: dict[str, list[int]] = {}
        for rid, spans in by_rule.items():
            spans.sort()
            self._starts[rid] = [a for a, _ in spans]
            running = 0
            ends: list[int] = []
            for _, b in spans:
                running = max(running, b)
                ends.append(running)
            self._max_end[rid] = ends

    def covers(self, rule: str, line: int) -> bool:
        starts = self._starts.get(rule)
        if not starts:
            return False
        i = bisect.bisect_right(starts, line) - 1
        return i >= 0 and self._max_end[rule][i] >= line
