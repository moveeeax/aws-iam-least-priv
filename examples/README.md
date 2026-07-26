# examples

- [`cloudtrail.json`](cloudtrail.json) — a small `{"Records": [...]}` sample with events
  from two different roles.
- [`current-policy.json`](current-policy.json) — an over-broad policy (`s3:*`,
  unused `dynamodb:DeleteTable`, `iam:PassRole`) to diff against.

```bash
aws-iam-least-priv analyze \
  --role app-runtime \
  --from-file cloudtrail.json \
  --current current-policy.json \
  --out policy.json
```

The proposed `policy.json` grants only `s3:GetObject`/`s3:PutObject` (scoped to the
observed bucket objects) and `dynamodb:GetItem`, and the diff flags `s3:*` to tighten
plus `dynamodb:DeleteTable` and `iam:PassRole` to remove.
