"""boto3-backed CloudTrail event source (imported only when querying live AWS)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .events import EventSource


class CloudTrailEventSource(EventSource):
    """Pulls events from the CloudTrail LookupEvents API over a time window."""

    def __init__(self, days: int = 30, region: str = "", profile: str = ""):
        self.days = days
        self.region = region
        self.profile = profile

    def _client(self):
        import boto3  # lazy: keeps the dependency out of the unit-tested core

        session_kwargs = {}
        if self.profile:
            session_kwargs["profile_name"] = self.profile
        session = boto3.Session(**session_kwargs)
        client_kwargs = {}
        if self.region:
            client_kwargs["region_name"] = self.region
        return session.client("cloudtrail", **client_kwargs)

    def events(self) -> Iterable[dict]:
        client = self._client()
        start = datetime.now(timezone.utc) - timedelta(days=self.days)
        paginator = client.get_paginator("lookup_events")
        for page in paginator.paginate(StartTime=start):
            for ev in page.get("Events", []):
                raw = ev.get("CloudTrailEvent")
                if not raw:
                    continue
                try:
                    yield json.loads(raw)
                except json.JSONDecodeError:
                    continue
