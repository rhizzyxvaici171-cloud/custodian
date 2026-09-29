"""Command-line entry point for Custodian."""

import argparse
import os
import sys

from . import __version__
from .baseline import (
    build_manifest, save_signed_baseline, load_and_verify_baseline,
    diff_manifests, BaselineTamperedError,
)
from .report import print_diff_report, diff_to_json


def build_parser():
    parser = argparse.ArgumentParser(
        prog="custodian",
        description="File integrity monitor: baseline a directory, then detect what changed.",
    )
    parser.add_argument("--version", action="version", version=f"custodian {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    baseline_parser = subparsers.add_parser("baseline", help="Record a signed baseline of a directory")
    baseline_parser.add_argument("path", help="Directory to baseline")
    baseline_parser.add_argument("--out", default=".custodian-baseline.json", help="Where to write the baseline file (default: .custodian-baseline.json)")
    baseline_parser.add_argument("--key", default=None, help="Signing key. If omitted, reads the CUSTODIAN_KEY environment variable instead (preferred, keeps it out of shell history).")

    check_parser = subparsers.add_parser("check", help="Compare a directory against a previously recorded baseline")
    check_parser.add_argument("path", help="Directory to check")
    check_parser.add_argument("--baseline", default=".custodian-baseline.json", help="Path to the baseline file (default: .custodian-baseline.json)")
    check_parser.add_argument("--key", default=None, help="Signing key used when the baseline was created. If omitted, reads CUSTODIAN_KEY.")
    check_parser.add_argument("--json", action="store_true", help="Output the diff as JSON")
    check_parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")

    return parser


def resolve_key(cli_key):
    key = cli_key or os.environ.get("CUSTODIAN_KEY")
    if not key:
        print(
            "Error: no signing key given. Pass --key, or set the CUSTODIAN_KEY "
            "environment variable (preferred, so the key doesn't end up in "
            "your shell history).",
            file=sys.stderr,
        )
        sys.exit(2)
    return key


def cmd_baseline(args):
    key = resolve_key(args.key)
    out_path = os.path.abspath(args.out)
    manifest = build_manifest(args.path, exclude_paths={out_path})
    save_signed_baseline(out_path, manifest, key)
    print(f"Baseline recorded: {len(manifest)} file(s) tracked, saved to {out_path}")
    return 0


def cmd_check(args):
    key = resolve_key(args.key)
    baseline_path = os.path.abspath(args.baseline)

    try:
        baseline_manifest = load_and_verify_baseline(baseline_path, key)
    except FileNotFoundError:
        print(f"Error: no baseline file found at {baseline_path}. Run 'custodian baseline' first.", file=sys.stderr)
        return 2
    except BaselineTamperedError as e:
        print(f"CRITICAL: {e}", file=sys.stderr)
        return 3

    current_manifest = build_manifest(args.path, exclude_paths={baseline_path})
    diff = diff_manifests(baseline_manifest, current_manifest)

    if args.json:
        print(diff_to_json(diff))
    else:
        print_diff_report(diff, use_color=not args.no_color)

    total_changes = (
        len(diff["added"]) + len(diff["removed"]) + len(diff["modified"])
        + len(diff["permission_changes"])
    )
    return 1 if total_changes > 0 else 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "baseline":
        return cmd_baseline(args)
    elif args.command == "check":
        return cmd_check(args)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)
