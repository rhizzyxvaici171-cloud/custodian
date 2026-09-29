"""Formats a diff result for terminal or JSON output."""

import json

COLORS = {
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}


def _c(text, color, use_color):
    if not use_color:
        return text
    return f"{COLORS[color]}{text}{COLORS['reset']}"


def print_diff_report(diff, use_color=True):
    total_changes = (
        len(diff["added"]) + len(diff["removed"]) + len(diff["modified"])
        + len(diff["permission_changes"])
    )

    if total_changes == 0:
        print(_c("✓ No changes since the baseline.", "bold", use_color))
        return

    for path in diff["modified"]:
        flag = " ⚠ newly world-writable" if path in diff["newly_world_writable"] else ""
        print(f"[{_c('MODIFIED', 'red', use_color)}] {path}{_c(flag, 'yellow', use_color)}")

    for path in diff["added"]:
        flag = " ⚠ world-writable" if path in diff["newly_world_writable"] else ""
        print(f"[{_c('ADDED', 'yellow', use_color)}]    {path}{_c(flag, 'yellow', use_color)}")

    for path in diff["removed"]:
        print(f"[{_c('REMOVED', 'dim', use_color)}]  {path}")

    for change in diff["permission_changes"]:
        old_octal = oct(change["old_mode"])[2:].zfill(3)
        new_octal = oct(change["new_mode"])[2:].zfill(3)
        flag = " ⚠ newly world-writable" if change["path"] in diff["newly_world_writable"] else ""
        print(f"[{_c('PERMISSIONS', 'yellow', use_color)}] {change['path']} "
              f"({old_octal} -> {new_octal}){_c(flag, 'yellow', use_color)}")

    print()
    summary = (
        f"{len(diff['modified'])} modified, {len(diff['added'])} added, "
        f"{len(diff['removed'])} removed, {len(diff['permission_changes'])} permission change(s)."
    )
    print(_c(summary, "bold", use_color))

    if diff["newly_world_writable"]:
        print(_c(
            f"\n⚠ {len(diff['newly_world_writable'])} file(s) are now world-writable, "
            "worth checking whether that was intentional.",
            "yellow", use_color,
        ))


def diff_to_json(diff):
    return json.dumps(diff, indent=2, sort_keys=True)
