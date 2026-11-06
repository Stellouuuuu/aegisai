"""Minimal JSONPath subset: $.a.b, $.a[0].b, $['a-b'][1]. No dependency."""

from __future__ import annotations

import re
from typing import Any

_TOKEN = re.compile(r"\.([A-Za-z_][\w-]*)|\[(\d+)\]|\[\'([^\']+)\'\]|\[\"([^\"]+)\"\]")


class JsonPathError(ValueError):
    pass


def parse(path: str) -> list[str | int]:
    if not path.startswith("$"):
        raise JsonPathError(f"JSONPath must start with '$': {path!r}")
    rest, pos, out = path[1:], 0, []
    while pos < len(rest):
        m = _TOKEN.match(rest, pos)
        if not m:
            raise JsonPathError(f"Unsupported JSONPath syntax at {rest[pos:]!r} in {path!r}")
        key, idx, q1, q2 = m.groups()
        out.append(int(idx) if idx is not None else (key or q1 or q2))
        pos = m.end()
    return out


def extract(data: Any, path: str) -> Any:
    """Return the value at `path`; raise JsonPathError if it does not exist."""
    cur = data
    for seg in parse(path):
        try:
            cur = cur[seg]
        except (KeyError, IndexError, TypeError):
            raise JsonPathError(f"Path {path!r} not found in response") from None
    return cur
