# aws-iam-least-priv

> Right-size over-broad IAM roles using what they actually did, per CloudTrail.

**Status:** 🚧 In development

## Overview

Analyze CloudTrail activity for a role and propose a least-privilege IAM policy based on actually-used actions.

## Features

- Ingest CloudTrail events (Athena query or downloaded logs) for a target role
- Aggregate the distinct API actions and resources the role used
- Synthesize a tightened IAM policy document from observed usage
- Diff the proposed policy against the currently attached policies
- Flag unused broad permissions to remove

## Stack

Python 3.11, `boto3`, CloudTrail/Athena, IAM policy synthesis.

## Usage

```bash
aws-iam-least-priv analyze --role app-runtime --days 30 --out policy.json
```

## License

MIT
