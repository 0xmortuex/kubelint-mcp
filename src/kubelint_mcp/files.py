"""Sandboxed file access.

Every path an agent supplies is resolved (symlinks included) and must stay inside the --dir root.
Files are size-capped and must be UTF-8.
"""

from __future__ import annotations

import os

from .errors import UserError, shorten

MAX_BYTES = 2_000_000
MAX_FILES = 300
MAX_TOTAL_BYTES = 20_000_000
YAML_EXTS = (".yaml", ".yml")
_SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", ".tox", ".mypy_cache"}


def _inside(root: str, path: str) -> bool:
    r, p = os.path.normcase(root), os.path.normcase(path)
    if p == r:
        return True
    try:
        return os.path.commonpath([r, p]) == r
    except ValueError:  # different drives on Windows
        return False


def real_path(path: str) -> str:
    """os.path.realpath, but a path the OS cannot resolve is a UserError. Python 3.10 on Windows raises a
    bare ValueError ("path too long") where newer versions raise OSError or return the path."""
    try:
        return os.path.realpath(path)
    except (OSError, ValueError) as e:
        raise UserError(f"{shorten(path)!r} cannot be resolved as a path ({type(e).__name__}: {shorten(str(e))})") from e


class Sandbox:
    def __init__(self, root: str) -> None:
        self.root = real_path(root)
        if not os.path.isdir(self.root):
            raise UserError(f"--dir {shorten(root)!r} is not a directory")

    def resolve(self, path: str) -> str:
        if not path or "\x00" in path:
            raise UserError("path is empty or contains a NUL byte")
        try:
            cand = path if os.path.isabs(path) else os.path.join(self.root, path)
        except (OSError, ValueError) as e:
            raise UserError(f"{shorten(path)!r} is not a usable path ({type(e).__name__})") from e
        real = real_path(cand)
        if not _inside(self.root, real):
            raise UserError(
                f"{shorten(path)!r} is outside the directory this server is allowed to read ({self.root}). "
                "Start the server with --dir pointing at your manifests."
            )
        return real

    def display(self, real: str) -> str:
        try:
            rel = os.path.relpath(real, self.root)
        except ValueError:
            return real
        return rel.replace(os.sep, "/")

    def read_text(self, path: str) -> tuple[str, str]:
        real = self.resolve(path)
        if not os.path.exists(real):
            raise UserError(f"File not found: {shorten(path)!r}. Relative paths are resolved against {self.root}.")
        if os.path.isdir(real):
            raise UserError(f"{shorten(path)!r} is a directory, not a file.")
        return real, read_real(real, shorten(path))

    def collect(self, path: str) -> tuple[list[str], bool, bool]:
        """Real paths of the YAML files at `path`: the file itself, or every .yaml/.yml under a directory.
        Returns (paths, was_directory, truncated)."""
        real = self.resolve(path)
        if not os.path.exists(real):
            raise UserError(f"Not found: {shorten(path)!r}. Relative paths are resolved against {self.root}.")
        if not os.path.isdir(real):
            return [real], False, False
        found: list[str] = []
        truncated = False
        try:
            for dirpath, dirnames, filenames in os.walk(real, followlinks=False):
                dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
                for fn in sorted(filenames):
                    if not fn.lower().endswith(YAML_EXTS):
                        continue
                    cand = os.path.join(dirpath, fn)
                    if not os.path.isfile(cand) or not self.contains(cand):
                        continue
                    if len(found) >= MAX_FILES:
                        truncated = True
                        break
                    found.append(cand)
                if truncated:
                    break
        except OSError as e:
            raise UserError(f"cannot list {shorten(path)!r}: {e.strerror or type(e).__name__}") from e
        if not found:
            raise UserError(f"No .yaml/.yml files found under {shorten(path)!r}.")
        return found, True, truncated

    def contains(self, candidate: str) -> bool:
        return _inside(self.root, real_path(candidate))


def read_real(real: str, label: str) -> str:
    try:
        size = os.path.getsize(real)
        if size > MAX_BYTES:
            raise UserError(f"{label!r} is {size} bytes; the limit is {MAX_BYTES}.")
        with open(real, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
    except OSError as e:
        raise UserError(f"cannot read {label!r}: {e.strerror or type(e).__name__}") from e
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise UserError(f"{label!r} is not valid UTF-8 text ({e.reason} at byte {e.start}).") from e
