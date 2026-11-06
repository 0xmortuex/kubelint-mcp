"""Finding records shared by every rule family."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Hit:
    """What a rule function reports. Severity is optional: the rule's default is used when None."""

    file: str
    line: int
    resource: str
    message: str
    fix: str
    severity: str | None = None


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    resource: str
    message: str
    fix: str
