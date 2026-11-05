# aws-iam-least-priv

[![ci](https://github.com/moveeeax/aws-iam-least-priv/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-iam-least-priv/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> Right-size over-broad IAM roles using what they actually did, per CloudTrail.

Most IAM roles are provisioned with far more than they use — `s3:*` when the app
only reads two prefixes, `iam:PassRole` left over from setup. `aws-iam-least-priv`
looks at what a role **actually did** in CloudTrail over a window, synthesizes a
tight policy from the observed actions, and diffs it against what's currently
attached so you can see exactly what to remove.

> ⚠️ **Review before applying.** The proposal reflects only activity within the
> chosen window; rarely-used but legitimate actions (monthly jobs, break-glass)
> may not appear. Treat the output as a strong starting point, not a rubber stamp.

## What it does

- Ingests CloudTrail events for a target role (a downloaded log file, or live via
  the LookupEvents API).
- Aggregates the distinct API actions and the resource ARNs the role touched.
- Synthesizes a least-privilege policy — one statement per service, resources
  scoped to what was seen (or `*` when nothing was, which the diff flags).
- Diffs against the current policy: **unused** grants to remove, **broad**
  wildcards to tighten, and any **missing** actions the role used but lacks.

## Install

Not published on PyPI; install straight from a tagged release on GitHub
(Python 3.11+):

```bash
pip install "git+https://github.com/moveeeax/aws-iam-least-priv@v0.1.1"
```

## Usage

```bash
# Live, from CloudTrail over the last 30 days
aws-iam-least-priv analyze --role app-runtime --days 30 --out policy.json

# Offline, from a downloaded CloudTrail log, diffing the attached policy
aws-iam-least-priv analyze \
  --role app-runtime \
  --from-file cloudtrail.json \
  --current current-policy.json \
  --out policy.json
```

```
# 3 action(s) across 2 service(s) from 3 event(s).

# Diff vs current policy
  remove (granted, unused): dynamodb:DeleteTable, iam:PassRole
  tighten (broad wildcards): s3:*
```

By default each statement's `Resource` is scoped to the ARNs observed for that
service. Pass `--wildcard-resources` to emit `"Resource": "*"` in every statement
instead, e.g. when the events don't carry resource ARNs and you plan to scope by
hand.

Live mode uses the standard AWS credential chain (`--profile` / `--region`
supported) and needs `cloudtrail:LookupEvents`.

## How it works

Each CloudTrail event maps to an IAM action (`eventSource` → service prefix, plus
`eventName`), filtered to the target role by its `sessionIssuer` or ARN. Actions
are grouped by service into statements, and observed resource ARNs scope each one.
The CloudTrail access sits behind an `EventSource` interface, so aggregation,
synthesis, and the diff are unit-tested against fixtures with no AWS calls — `boto3`
is imported lazily only in live mode.

## Development

```bash
make install   # pip install -e ".[dev]"
make test      # pytest -q
make lint      # ruff check src tests
```

## License

MIT — see [LICENSE](LICENSE).

---

**Archived on 2026-11-05.** IAM Access Analyzer policy generation does the same CloudTrail-to-policy synthesis natively (org trails, 90 days, resource-level where supported), plus unused-access findings; iamlive and Repokid cover the live/pruning variants. The naive eventSource:eventName mapping here is also wrong for many services (e.g. eventName != IAM action, S3 data events), which Access Analyzer handles. No clear angle beyond "works offline on a log file".
