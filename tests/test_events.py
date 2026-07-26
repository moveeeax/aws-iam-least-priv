import json
import os

from aws_iam_least_priv.events import (
    FileEventSource,
    action_of,
    aggregate,
    matches_role,
    service_prefix,
)

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "examples", "cloudtrail.json")


def test_service_prefix():
    assert service_prefix("s3.amazonaws.com") == "s3"
    assert service_prefix("monitoring.amazonaws.com") == "cloudwatch"


def test_action_of():
    assert action_of("s3.amazonaws.com", "GetObject") == "s3:GetObject"


def test_matches_role_by_session_issuer():
    ev = {"userIdentity": {"sessionContext": {"sessionIssuer": {"userName": "app-runtime"}}}}
    assert matches_role(ev, "app-runtime")
    assert not matches_role(ev, "other")


def test_matches_role_by_arn():
    ev = {"userIdentity": {"arn": "arn:aws:iam::1:role/deploy"}}
    assert matches_role(ev, "deploy")


def test_aggregate_filters_role_and_collects():
    with open(FIXTURE) as f:
        records = json.load(f)["Records"]
    usage = aggregate(records, "app-runtime")
    # DeleteBucket belongs to other-role and must be excluded.
    assert usage.actions == {"s3:GetObject", "s3:PutObject", "dynamodb:GetItem"}
    assert usage.event_count == 3
    assert usage.services() == ["dynamodb", "s3"]
    assert "arn:aws:s3:::my-bucket/data.csv" in usage.resources_by_service["s3"]


def test_file_event_source_records_and_array(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps([{"eventSource": "s3.amazonaws.com", "eventName": "GetObject"}]))
    evs = list(FileEventSource(str(p)).events())
    assert len(evs) == 1

    p2 = tmp_path / "b.json"
    p2.write_text(json.dumps({"Records": [{"eventSource": "ec2.amazonaws.com", "eventName": "RunInstances"}]}))
    assert len(list(FileEventSource(str(p2)).events())) == 1
