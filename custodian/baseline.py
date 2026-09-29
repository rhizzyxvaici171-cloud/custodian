"""
Builds a manifest of every file in a directory tree (path, hash, size,
permission bits), and compares two manifests to find what changed.
"""

import json
import os
import stat as stat_module

from .hashing import hash_file, sign, verify_signature

DEFAULT_EXCLUDED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    ".mypy_cache", ".pytest_cache", "dist", "build",
}

# A file becoming writable by "others" is worth calling out specifically,
# it's a common, meaningful sign of either a misconfiguration or tampering.
WORLD_WRITABLE_BIT = 0o002


def build_manifest(root_dir, exclude_dirs=None, exclude_paths=None):
    """
    Walks root_dir and returns {relative_path: {"hash", "size", "mode"}}.
    exclude_paths is a set of absolute paths to skip entirely, used to
    keep a baseline file stored inside the monitored directory from
    trying to include a hash of itself.
    """
    exclude_dirs = DEFAULT_EXCLUDED_DIRS | (exclude_dirs or set())
    exclude_paths = {os.path.abspath(p) for p in (exclude_paths or set())}
    root_dir = os.path.abspath(root_dir)

    manifest = {}
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            if full_path in exclude_paths:
                continue
            if os.path.islink(full_path):
                continue  # don't follow symlinks; hash the target's owner's problem
            try:
                st = os.stat(full_path)
                file_hash = hash_file(full_path)
            except (OSError, PermissionError):
                continue
            rel_path = os.path.relpath(full_path, root_dir)
            manifest[rel_path] = {
                "hash": file_hash,
                "size": st.st_size,
                "mode": stat_module.S_IMODE(st.st_mode),
            }
    return manifest


def diff_manifests(baseline, current):
    """
    Compares two manifests (as produced by build_manifest) and returns a
    dict describing what changed: modified content, added files, removed
    files, and permission changes on otherwise-unmodified files, plus a
    specific flag for anything that newly became world-writable.
    """
    baseline_paths = set(baseline.keys())
    current_paths = set(current.keys())

    added = sorted(current_paths - baseline_paths)
    removed = sorted(baseline_paths - current_paths)

    modified = []
    permission_changes = []
    newly_world_writable = []

    for path in sorted(baseline_paths & current_paths):
        old, new = baseline[path], current[path]
        if old["hash"] != new["hash"]:
            modified.append(path)
        elif old["mode"] != new["mode"]:
            permission_changes.append({"path": path, "old_mode": old["mode"], "new_mode": new["mode"]})

        old_world_writable = bool(old["mode"] & WORLD_WRITABLE_BIT)
        new_world_writable = bool(new["mode"] & WORLD_WRITABLE_BIT)
        if new_world_writable and not old_world_writable:
            newly_world_writable.append(path)

    return {
        "added": added,
        "removed": removed,
        "modified": modified,
        "permission_changes": permission_changes,
        "newly_world_writable": newly_world_writable,
    }


def save_signed_baseline(baseline_file_path, manifest, key):
    manifest_json = json.dumps(manifest, sort_keys=True).encode("utf-8")
    signature = sign(manifest_json, key)
    payload = {"manifest": manifest, "signature": signature}
    with open(baseline_file_path, "w") as f:
        json.dump(payload, f, indent=2, sort_keys=True)


class BaselineTamperedError(Exception):
    """Raised when a baseline file's stored signature doesn't match its
    content under the given key, meaning either the wrong key was
    supplied, or the baseline file was modified after it was created."""


def load_and_verify_baseline(baseline_file_path, key):
    with open(baseline_file_path, "r") as f:
        payload = json.load(f)

    manifest = payload["manifest"]
    stored_signature = payload["signature"]
    manifest_json = json.dumps(manifest, sort_keys=True).encode("utf-8")

    if not verify_signature(manifest_json, key, stored_signature):
        raise BaselineTamperedError(
            "The baseline file's signature doesn't match its content. "
            "Either the wrong key was provided, or the baseline file "
            "itself has been modified since it was created."
        )
    return manifest
