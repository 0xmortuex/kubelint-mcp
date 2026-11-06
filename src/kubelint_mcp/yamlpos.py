"""YAML loading that remembers where every value came from.

PyYAML's safe loader throws line numbers away when it builds Python objects. Here we compose the node
graph first (yaml.SafeLoader.get_node, which never constructs arbitrary objects), then convert it ourselves
while recording, for every mapping key and sequence item, its line, column and (for scalars) end line.

Two guards live here because this is the first code to touch untrusted text:

* alias bombs: an alias reuses the same node, so the graph is small but the *expanded* tree can be
  astronomically large. We compute the expanded size with memoization (linear in the graph) and refuse
  documents above MAX_EXPANDED_NODES;
* depth: conversion refuses nesting deeper than MAX_DEPTH, and a RecursionError inside PyYAML's own
  recursive composer is reported as a parse problem.
"""

from __future__ import annotations

from collections.abc import Hashable
from dataclasses import dataclass, field
from typing import Any, NamedTuple

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

MAX_EXPANDED_NODES = 200_000
MAX_DEPTH = 80
MAX_DOCS = 1000

Path = tuple[Any, ...]


class Pos(NamedTuple):
    line: int  # 1-based
    col: int  # 0-based
    end_line: int  # last line of a scalar value; equals line otherwise


@dataclass
class Doc:
    index: int
    root: Any
    pos: dict[Path, Pos]
    flow: set[Path]
    dups: list[tuple[Path, str, int]]
    start_line: int

    def line(self, path: Path) -> int:
        """Line of the deepest recorded ancestor of `path` (the path itself when it was written)."""
        while path:
            p = self.pos.get(path)
            if p is not None:
                return p.line
            path = path[:-1]
        return self.start_line

    def position(self, path: Path) -> Pos | None:
        return self.pos.get(path)


@dataclass
class ParseProblem:
    line: int
    message: str


class _DocError(Exception):
    def __init__(self, line: int, message: str) -> None:
        super().__init__(message)
        self.line = line
        self.message = message


@dataclass
class LoadResult:
    docs: list[Doc] = field(default_factory=list)
    problems: list[ParseProblem] = field(default_factory=list)
    truncated: bool = False


def _clip(text: str, limit: int = 160) -> str:
    text = text.replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "..."


def describe_yaml_error(e: yaml.YAMLError) -> ParseProblem:
    """A message without PyYAML's source snippet: the snippet would echo the offending line, which may
    hold a secret."""
    if isinstance(e, yaml.MarkedYAMLError):
        mark = e.problem_mark or e.context_mark
        line = (mark.line + 1) if mark is not None else 1
        col = (mark.column + 1) if mark is not None else 1
        problem = e.problem or "invalid YAML"
        ctx = f"{e.context}: " if e.context else ""
        return ParseProblem(line, f"YAML parse error: {_clip(ctx + problem)} (line {line}, column {col})")
    return ParseProblem(1, f"YAML parse error: {_clip(str(e))}")


class _Converter:
    def __init__(self, loader: yaml.SafeLoader) -> None:
        self.loader = loader
        self.memo: dict[int, tuple[Any, int]] = {}
        self.active: set[int] = set()
        self.pos: dict[Path, Pos] = {}
        self.flow: set[Path] = set()
        self.dups: list[tuple[Path, str, int]] = []

    def scalar(self, node: ScalarNode) -> Any:
        try:
            return self.loader.construct_object(node, deep=True)
        except yaml.YAMLError as e:
            raise _DocError(node.start_mark.line + 1, f"unsupported value: {_clip(getattr(e, 'problem', None) or 'cannot construct')}") from e

    def convert(self, node: Node, path: Path, depth: int) -> tuple[Any, int]:
        if depth > MAX_DEPTH:
            raise _DocError(node.start_mark.line + 1, f"nesting deeper than {MAX_DEPTH} levels")
        nid = id(node)
        hit = self.memo.get(nid)
        if hit is not None:
            return hit
        if nid in self.active:
            raise _DocError(node.start_mark.line + 1, "recursive alias (a node contains itself)")
        self.active.add(nid)
        try:
            result = self._convert(node, path, depth)
        finally:
            self.active.discard(nid)
        self.memo[nid] = result
        return result

    def _convert(self, node: Node, path: Path, depth: int) -> tuple[Any, int]:
        if isinstance(node, ScalarNode):
            return self.scalar(node), 1
        if isinstance(node, SequenceNode):
            if node.flow_style:
                self.flow.add(path)
            items: list[Any] = []
            size = 1
            for i, child in enumerate(node.value):
                cpath = path + (i,)
                self.pos[cpath] = Pos(child.start_mark.line + 1, child.start_mark.column, child.start_mark.line + 1)
                value, s = self.convert(child, cpath, depth + 1)
                items.append(value)
                size += s
                if size > MAX_EXPANDED_NODES:
                    raise _DocError(node.start_mark.line + 1, _BOMB)
            return items, size
        if isinstance(node, MappingNode):
            if node.flow_style:
                self.flow.add(path)
            explicit: dict[Any, Any] = {}
            merged: dict[Any, Any] = {}
            size = 1
            for knode, vnode in node.value:
                if isinstance(knode, ScalarNode) and knode.tag == "tag:yaml.org,2002:merge":
                    sources = vnode.value if isinstance(vnode, SequenceNode) else [vnode]
                    for src in reversed(sources):
                        if not isinstance(src, MappingNode):
                            raise _DocError(src.start_mark.line + 1, "merge key (<<) needs a mapping")
                        mvalue, s = self.convert(src, path + ("<<",), depth + 1)
                        merged.update(mvalue)
                        size += s
                    self.pos[path + ("<<",)] = Pos(knode.start_mark.line + 1, knode.start_mark.column, knode.start_mark.line + 1)
                    if size > MAX_EXPANDED_NODES:
                        raise _DocError(node.start_mark.line + 1, _BOMB)
                    continue
                if not isinstance(knode, ScalarNode):
                    raise _DocError(knode.start_mark.line + 1, "mapping keys must be scalars")
                key = self.scalar(knode)
                if not isinstance(key, Hashable):
                    raise _DocError(knode.start_mark.line + 1, "unhashable mapping key")
                pkey = key if isinstance(key, str) else str(key)
                cpath = path + (pkey,)
                end = vnode.end_mark.line + 1 if isinstance(vnode, ScalarNode) else knode.start_mark.line + 1
                if key in explicit:
                    self.dups.append((cpath, pkey, knode.start_mark.line + 1))
                self.pos[cpath] = Pos(knode.start_mark.line + 1, knode.start_mark.column, max(end, knode.start_mark.line + 1))
                value, s = self.convert(vnode, cpath, depth + 1)
                explicit[key] = value
                size += s + 1
                if size > MAX_EXPANDED_NODES:
                    raise _DocError(node.start_mark.line + 1, _BOMB)
            merged.update(explicit)
            return merged, size
        raise _DocError(node.start_mark.line + 1, "unsupported YAML node")


_BOMB = (
    f"alias expansion is larger than {MAX_EXPANDED_NODES} nodes (a billion-laughs style document); "
    "refusing to expand it"
)


def load_documents(text: str) -> LoadResult:
    """Parse every YAML document in `text`; never raises on bad input, reports ParseProblem instead."""
    result = LoadResult()
    loader = yaml.SafeLoader(text)
    index = 0
    try:
        while loader.check_node():
            node = loader.get_node()
            if node is None:
                break
            if index >= MAX_DOCS:
                result.truncated = True
                break
            try:
                conv = _Converter(loader)
                root, _ = conv.convert(node, (), 0)
                conv.pos[()] = Pos(node.start_mark.line + 1, node.start_mark.column, node.start_mark.line + 1)
                result.docs.append(
                    Doc(index, root, conv.pos, conv.flow, conv.dups, node.start_mark.line + 1)
                )
            except _DocError as e:
                result.problems.append(ParseProblem(e.line, f"YAML problem: {e.message}"))
            except RecursionError:
                result.problems.append(ParseProblem(node.start_mark.line + 1, "YAML problem: nested too deeply to analyze"))
            index += 1
    except yaml.YAMLError as e:
        result.problems.append(describe_yaml_error(e))
    except RecursionError:
        result.problems.append(ParseProblem(1, "YAML problem: nested too deeply to analyze"))
    finally:
        loader.dispose()
    return result
