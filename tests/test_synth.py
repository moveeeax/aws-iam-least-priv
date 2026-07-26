from aws_iam_least_priv.events import Usage
from aws_iam_least_priv.synth import synthesize


def make_usage():
    u = Usage()
    u.add("s3:GetObject", ["arn:aws:s3:::b/a"])
    u.add("s3:PutObject", ["arn:aws:s3:::b/c"])
    u.add("dynamodb:GetItem", [])
    return u


def test_synthesize_groups_by_service():
    pol = synthesize(make_usage())
    assert pol["Version"] == "2012-10-17"
    sids = {s["Sid"] for s in pol["Statement"]}
    assert sids == {"AllowS3", "AllowDynamodb"}


def test_synthesize_scopes_resources_when_known():
    pol = synthesize(make_usage())
    s3 = next(s for s in pol["Statement"] if s["Sid"] == "AllowS3")
    assert sorted(s3["Action"]) == ["s3:GetObject", "s3:PutObject"]
    assert s3["Resource"] == ["arn:aws:s3:::b/a", "arn:aws:s3:::b/c"]
    # dynamodb had no observed ARNs -> falls back to "*"
    ddb = next(s for s in pol["Statement"] if s["Sid"] == "AllowDynamodb")
    assert ddb["Resource"] == "*"


def test_wildcard_resources_forces_star():
    pol = synthesize(make_usage(), wildcard_resources=True)
    assert all(s["Resource"] == "*" for s in pol["Statement"])


def test_single_arn_is_scalar():
    u = Usage()
    u.add("s3:GetObject", ["arn:aws:s3:::only/one"])
    pol = synthesize(u)
    assert pol["Statement"][0]["Resource"] == "arn:aws:s3:::only/one"
