import json
import os

from aws_iam_least_priv.diff import collect_actions, diff
from aws_iam_least_priv.events import aggregate

HERE = os.path.dirname(__file__)


def load(name):
    with open(os.path.join(HERE, "..", "examples", name)) as f:
        return json.load(f)


def test_collect_actions_flattens():
    pol = {"Statement": [
        {"Effect": "Allow", "Action": "s3:*"},
        {"Effect": "Allow", "Action": ["ec2:DescribeInstances", "ec2:StopInstances"]},
        {"Effect": "Deny", "Action": "iam:*"},
    ]}
    assert collect_actions(pol) == ["s3:*", "ec2:DescribeInstances", "ec2:StopInstances"]


def test_diff_flags_unused_broad_and_missing():
    usage = aggregate(load("cloudtrail.json")["Records"], "app-runtime")
    d = diff(usage, load("current-policy.json"))

    # s3:* is a broad wildcard and covers the used s3 actions (so not "unused").
    assert "s3:*" in d.broad
    assert "s3:*" not in d.unused
    # dynamodb:DeleteTable was granted but never used.
    assert "dynamodb:DeleteTable" in d.unused
    # iam:PassRole granted, never used.
    assert "iam:PassRole" in d.unused
    # everything used is covered by s3:* / dynamodb:GetItem -> nothing missing.
    assert d.missing == []


def test_diff_reports_missing():
    usage = aggregate(load("cloudtrail.json")["Records"], "app-runtime")
    narrow = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject"}]}
    d = diff(usage, narrow)
    assert "s3:PutObject" in d.missing
    assert "dynamodb:GetItem" in d.missing


def test_wildcard_covers_case_insensitive():
    usage = aggregate([{"eventSource": "s3.amazonaws.com", "eventName": "GetObject",
                        "userIdentity": {"sessionContext": {"sessionIssuer": {"userName": "r"}}}}], "r")
    d = diff(usage, {"Statement": [{"Effect": "Allow", "Action": "s3:Get*"}]})
    assert d.missing == []
