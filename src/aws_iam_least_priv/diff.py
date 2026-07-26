"""Diff observed usage against a currently attached IAM policy."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from .events import Usage


def collect_actions(policy: Dict[str, Any]) -> List[str]:
    """Return every action granted by Allow statements in a policy document."""
    out: List[str] = []
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if st.get("Effect") != "Allow":
            continue
        actions = st.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        out.extend(actions)
    return out


def _covers(granted: str, used: str) -> bool:
    """Whether a granted action (possibly a wildcard like `s3:*` or `*`) covers a used one."""
    if granted == "*":
        return True
    return fnmatch.fnmatchcase(used.lower(), granted.lower())


@dataclass
class Diff:
    used: List[str] = field(default_factory=list)
    unused: List[str] = field(default_factory=list)   # granted but never exercised
    broad: List[str] = field(default_factory=list)    # wildcard grants
    missing: List[str] = field(default_factory=list)  # used but not granted


def diff(usage: Usage, current: Dict[str, Any]) -> Diff:
    """Compare observed usage against the current policy.

    - unused: granted actions no observed call matched (candidates to remove)
    - broad:  wildcard grants (`*`, `svc:*`, `svc:Get*`) that should be tightened
    - missing: actions the role used but the current policy does not grant
    """
    granted = collect_actions(current)
    used: Set[str] = set(usage.actions)

    unused, broad = [], []
    for g in sorted(set(granted)):
        if g == "*" or g.endswith(":*") or "*" in g:
            broad.append(g)
        if not any(_covers(g, u) for u in used):
            unused.append(g)

    missing = sorted(u for u in used if not any(_covers(g, u) for g in granted))

    return Diff(used=sorted(used), unused=unused, broad=broad, missing=missing)
