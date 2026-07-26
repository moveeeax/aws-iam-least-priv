import json
import os

from aws_iam_least_priv.cli import main

FIX = os.path.join(os.path.dirname(__file__), "..", "examples", "cloudtrail.json")
CUR = os.path.join(os.path.dirname(__file__), "..", "examples", "current-policy.json")


def test_analyze_writes_policy(tmp_path, capsys):
    out = tmp_path / "policy.json"
    rc = main(["analyze", "--role", "app-runtime", "--from-file", FIX, "--out", str(out)])
    assert rc == 0
    policy = json.loads(out.read_text())
    assert policy["Version"] == "2012-10-17"
    sids = {s["Sid"] for s in policy["Statement"]}
    assert sids == {"AllowS3", "AllowDynamodb"}


def test_analyze_stdout_and_diff(capsys):
    rc = main(["analyze", "--role", "app-runtime", "--from-file", FIX, "--current", CUR])
    assert rc == 0
    err = capsys.readouterr().err
    assert "Diff vs current policy" in err
    assert "dynamodb:DeleteTable" in err  # unused, flagged for removal


def test_analyze_no_activity_returns_1(tmp_path):
    empty = tmp_path / "e.json"
    empty.write_text(json.dumps({"Records": []}))
    rc = main(["analyze", "--role", "nobody", "--from-file", str(empty)])
    assert rc == 1


def test_unknown_role_no_activity(tmp_path):
    rc = main(["analyze", "--role", "ghost", "--from-file", FIX])
    assert rc == 1
