"""Command-line interface for aws-iam-least-priv."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .diff import diff as diff_usage
from .events import FileEventSource, aggregate
from .synth import synthesize


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-iam-least-priv",
        description="Propose a least-privilege IAM policy for a role from its CloudTrail activity.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analyze CloudTrail activity and synthesize a policy.")
    a.add_argument("--role", required=True, help="target IAM role name")
    a.add_argument("--days", type=int, default=30, help="look-back window in days (default 30)")
    a.add_argument("--from-file", help="read CloudTrail records from a JSON file instead of AWS")
    a.add_argument("--current", help="current attached policy JSON to diff against")
    a.add_argument("--out", default="-", help="write the proposed policy JSON here (default stdout)")
    a.add_argument("--wildcard-resources", action="store_true", help='force Resource "*" in every statement')
    a.add_argument("--region", default="", help="AWS region (live mode)")
    a.add_argument("--profile", default="", help="AWS profile (live mode)")
    return p


def _source(args):
    if args.from_file:
        return FileEventSource(args.from_file)
    from .awssource import CloudTrailEventSource  # lazy: avoids importing boto3 for file mode

    return CloudTrailEventSource(days=args.days, region=args.region, profile=args.profile)


def cmd_analyze(args) -> int:
    usage = aggregate(_source(args).events(), args.role)
    if not usage.actions:
        print(
            f"No CloudTrail activity found for role {args.role!r} in the window. "
            "Widen --days or check the role name.",
            file=sys.stderr,
        )
        return 1

    policy = synthesize(usage, wildcard_resources=args.wildcard_resources)
    rendered = json.dumps(policy, indent=2)
    if args.out and args.out != "-":
        with open(args.out, "w") as f:
            f.write(rendered + "\n")
        print(f"Wrote proposed policy to {args.out}", file=sys.stderr)
    else:
        print(rendered)

    print(
        f"\n# {len(usage.actions)} action(s) across {len(usage.services())} service(s) "
        f"from {usage.event_count} event(s).",
        file=sys.stderr,
    )

    if args.current:
        with open(args.current) as f:
            current = json.load(f)
        d = diff_usage(usage, current)
        _print_diff(d)
    return 0


def _print_diff(d) -> None:
    out = sys.stderr
    print("\n# Diff vs current policy", file=out)
    if d.unused:
        print(f"  remove (granted, unused): {', '.join(d.unused)}", file=out)
    if d.broad:
        print(f"  tighten (broad wildcards): {', '.join(d.broad)}", file=out)
    if d.missing:
        print(f"  note (used, not granted): {', '.join(d.missing)}", file=out)
    if not (d.unused or d.broad or d.missing):
        print("  current policy already matches observed usage.", file=out)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        return cmd_analyze(args)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
