"""Parse and aggregate CloudTrail events for a target IAM role."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Set


def service_prefix(event_source: str) -> str:
    """Map a CloudTrail eventSource to an IAM service prefix.

    e.g. "s3.amazonaws.com" -> "s3", "monitoring.amazonaws.com" -> "monitoring".
    The prefix is the label before the first dot; a handful of AWS services use
    an IAM prefix that differs from their eventSource, remapped here.
    """
    base = event_source.split(".", 1)[0]
    return _PREFIX_REMAP.get(base, base)


# eventSource label -> IAM action prefix, for the cases where they diverge.
_PREFIX_REMAP = {
    "monitoring": "cloudwatch",
    "email": "ses",
    "events": "events",
}


def action_of(event_source: str, event_name: str) -> str:
    """Build an IAM action string like `s3:GetObject`."""
    return f"{service_prefix(event_source)}:{event_name}"


def matches_role(event: dict, role: str) -> bool:
    """Report whether a CloudTrail event was performed by the target role."""
    ident = event.get("userIdentity", {}) or {}
    sess = (ident.get("sessionContext", {}) or {}).get("sessionIssuer", {}) or {}
    if sess.get("userName") == role:
        return True
    arn = ident.get("arn", "") or ""
    return (f":role/{role}" in arn) or (f":assumed-role/{role}/" in arn)


def _resource_arns(event: dict) -> List[str]:
    out = []
    for r in event.get("resources", []) or []:
        arn = r.get("ARN") or r.get("arn")
        if arn:
            out.append(arn)
    return out


@dataclass
class Usage:
    """Distinct actions used, and the resource ARNs seen per action."""

    actions: Set[str] = field(default_factory=set)
    resources_by_service: Dict[str, Set[str]] = field(default_factory=dict)
    event_count: int = 0

    def add(self, action: str, arns: Iterable[str]) -> None:
        self.actions.add(action)
        svc = action.split(":", 1)[0]
        bucket = self.resources_by_service.setdefault(svc, set())
        for a in arns:
            bucket.add(a)

    def services(self) -> List[str]:
        return sorted({a.split(":", 1)[0] for a in self.actions})

    def actions_for(self, service: str) -> List[str]:
        return sorted(a for a in self.actions if a.split(":", 1)[0] == service)


def aggregate(events: Iterable[dict], role: str) -> Usage:
    """Aggregate the distinct actions (and resources) the role actually used."""
    usage = Usage()
    for ev in events:
        if not matches_role(ev, role):
            continue
        source = ev.get("eventSource")
        name = ev.get("eventName")
        if not source or not name:
            continue
        usage.event_count += 1
        usage.add(action_of(source, name), _resource_arns(ev))
    return usage


class EventSource:
    """Seam over CloudTrail so the aggregation is testable without AWS."""

    def events(self) -> Iterable[dict]:  # pragma: no cover - interface
        raise NotImplementedError


class FileEventSource(EventSource):
    """Reads CloudTrail records from a downloaded log file.

    Accepts either a `{"Records": [...]}` document (CloudTrail log delivery) or a
    bare JSON array of event dicts.
    """

    def __init__(self, path: str):
        self.path = path

    def events(self) -> Iterable[dict]:
        with open(self.path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return list(data.get("Records", []))
        if isinstance(data, list):
            return data
        raise ValueError(f"unrecognized CloudTrail JSON in {self.path}")
