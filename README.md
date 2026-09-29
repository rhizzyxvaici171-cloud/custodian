# Custodian 🗝️

A file integrity monitor. Record a cryptographic baseline of a directory, then later find out exactly what was modified, added, removed, or had its permissions changed. Zero dependencies, pure Python standard library.

## Why this exists

Every other security tool in this portfolio looks at something at a single point in time: a password, a token, a URL, a policy, a commit. Custodian looks at change over time, the classic "Tripwire / AIDE" category of defensive tooling. It answers the question you ask after something feels off: *what is different about this system compared to when I knew it was good?*

## How it works

```bash
# 1. While you trust the directory's contents, record a signed baseline
export CUSTODIAN_KEY="a long passphrase you keep somewhere safe"
custodian baseline /etc/myapp --out /secure/location/baseline.json

# 2. Later (by hand, or from cron), check what changed
custodian check /etc/myapp --baseline /secure/location/baseline.json
```

```
[MODIFIED] config/settings.conf
[ADDED]    scripts/update.sh
[REMOVED]  app.py
[PERMISSIONS] scripts/deploy.sh (644 -> 646) ⚠ newly world-writable

1 modified, 1 added, 1 removed, 1 permission change(s).

⚠ 1 file(s) are now world-writable, worth checking whether that was intentional.
```

Each file is recorded with its SHA-256 hash, size, and permission bits. A file that becomes world-writable is called out specifically, since that is a common, meaningful sign of either a misconfiguration or tampering.

## The part most simple versions skip: protecting the baseline itself

A baseline file is just data. An attacker who changes a monitored file *and* edits the baseline to match leaves nothing for a naive integrity checker to find. This is the well-known weak point of the whole category.

Custodian signs the baseline with an HMAC-SHA256 over its contents, using a key you supply and **do not store next to it**. At check time the signature is verified first. If it doesn't match, the check refuses to continue, prints a `CRITICAL` error, and exits with code `3`, distinct from the "changes found" code.

This was demonstrated against a simulated attack rather than only a unit test: after tampering with a config file, the baseline JSON was edited directly to swap in the tampered file's new hash. Editing plain JSON needs no key, but forging the signature does, so the next `check` caught it.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No changes since the baseline |
| 1 | Changes found |
| 2 | Usage error (no key given, baseline file missing) |
| 3 | Baseline signature invalid: wrong key, or the baseline itself was modified |

## What this deliberately is not

- **Not real-time.** It compares two snapshots when you run it. Anything an attacker changes and then reverts between checks is invisible. Real-time monitoring (inotify, auditd, OSSEC) is a different tool.
- **Only as trustworthy as your key handling.** Whoever holds the signing key can forge a baseline. The HMAC raises the bar from "edit a text file" to "steal the key", it does not remove the problem. Keep the key and the baseline somewhere the monitored machine's users can't write.
- **Symlinks are not followed.** They're skipped rather than hashed.
- **Permission bits are Unix-flavored.** On Windows, mode bits are largely meaningless, so permission checks there tell you little.
- **It reads every file in full.** On a very large tree the first baseline and each check will take time proportional to the data size.
- **Not a replacement for AIDE, Tripwire, or OSSEC** on anything that actually matters. It's a small, readable, dependency-free tool that demonstrates the core idea correctly.

## Installation

```bash
git clone https://github.com/rhizzyxvaici171-cloud/custodian.git
cd custodian
pip install -e .
```

Prefer the `CUSTODIAN_KEY` environment variable over `--key`, so the key doesn't end up in your shell history or a process listing.

## Options

```bash
custodian baseline PATH [--out FILE] [--key KEY]
custodian check    PATH [--baseline FILE] [--key KEY] [--json] [--no-color]
```

Directories like `.git`, `node_modules`, `venv`, and `__pycache__` are skipped by default. If the baseline file is stored inside the watched directory, it is excluded from itself automatically (otherwise it would report on its own hash).

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

28 tests across two files. `test_custodian.py` covers hashing, signing, manifest building, and the diff logic. `test_cli.py` drives the real CLI against real temporary directories: modify, add, remove, wrong key, edited baseline, missing key, missing baseline, baseline stored inside the watched directory, and JSON output validity.

## Project structure

```
custodian/
├── custodian/
│   ├── __init__.py
│   ├── hashing.py    # SHA-256 file hashing, HMAC signing and constant-time verify
│   ├── baseline.py     # manifest building, diffing, signed baseline save/load
│   ├── report.py          # terminal and JSON output
│   └── cli.py                # argparse entry point
├── tests/
│   ├── test_custodian.py
│   └── test_cli.py
├── .github/workflows/ci.yml
├── pyproject.toml
└── README.md
```

## License

MIT, see [LICENSE](LICENSE).
