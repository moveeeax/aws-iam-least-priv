"""Synthesize a least-privilege IAM policy document from observed usage."""
from __future__ import annotations

from typing import Any, Dict, List

from .events import Usage


def synthesize(usage: Usage, wildcard_resources: bool = False) -> Dict[str, Any]:
    """Build an IAM policy granting exactly the actions the role used.

    One statement per service. Resources are scoped to the ARNs actually seen for
    that service; when none were observed (or wildcard_resources is set) the
    statement falls back to "*", which the report flags for manual scoping.
    """
    statements: List[Dict[str, Any]] = []
    for svc in usage.services():
        actions = usage.actions_for(svc)
        arns = sorted(usage.resources_by_service.get(svc, set()))
        if wildcard_resources or not arns:
            resource: Any = "*"
        elif len(arns) == 1:
            resource = arns[0]
        else:
            resource = arns
        statements.append({
            "Sid": _sid(svc),
            "Effect": "Allow",
            "Action": actions,
            "Resource": resource,
        })
    return {"Version": "2012-10-17", "Statement": statements}


def _sid(service: str) -> str:
    # Sids must be alphanumeric.
    return "Allow" + "".join(ch for ch in service.title() if ch.isalnum())
