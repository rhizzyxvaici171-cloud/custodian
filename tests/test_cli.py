import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from custodian.cli import main


def run_cli(args, env_key=None):
    """Runs the CLI in-process, returning (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    old_key = os.environ.pop("CUSTODIAN_KEY", None)
    if env_key is not None:
        os.environ["CUSTODIAN_KEY"] = env_key
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main(args)
            except SystemExit as e:
                code = e.code
    finally:
        os.environ.pop("CUSTODIAN_KEY", None)
        if old_key is not None:
            os.environ["CUSTODIAN_KEY"] = old_key
    return code, out.getvalue(), err.getvalue()


class TestCliEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.watched = os.path.join(self.tmpdir, "watched")
        os.makedirs(self.watched)
        self.baseline = os.path.join(self.tmpdir, "baseline.json")
        with open(os.path.join(self.watched, "a.txt"), "w") as f:
            f.write("original")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _baseline(self, key="k"):
        return run_cli(["baseline", self.watched, "--out", self.baseline], env_key=key)

    def _check(self, key="k", *extra):
        return run_cli(["check", self.watched, "--baseline", self.baseline, *extra], env_key=key)

    def test_clean_check_exits_zero(self):
        self._baseline()
        code, out, _ = self._check()
        self.assertEqual(code, 0)
        self.assertIn("No changes", out)

    def test_modified_file_exits_one_and_is_reported(self):
        self._baseline()
        with open(os.path.join(self.watched, "a.txt"), "w") as f:
            f.write("tampered")
        code, out, _ = self._check("k", "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("MODIFIED", out)
        self.assertIn("a.txt", out)

    def test_added_and_removed_files_reported(self):
        self._baseline()
        os.remove(os.path.join(self.watched, "a.txt"))
        with open(os.path.join(self.watched, "dropped.sh"), "w") as f:
            f.write("evil")
        code, out, _ = self._check("k", "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("ADDED", out)
        self.assertIn("REMOVED", out)

    def test_wrong_key_exits_three(self):
        self._baseline("right-key")
        code, _, err = self._check("wrong-key")
        self.assertEqual(code, 3)
        self.assertIn("CRITICAL", err)

    def test_edited_baseline_exits_three_even_with_correct_key(self):
        self._baseline("k")
        with open(os.path.join(self.watched, "a.txt"), "w") as f:
            f.write("tampered")
        with open(self.baseline) as f:
            payload = json.load(f)
        import hashlib
        payload["manifest"]["a.txt"]["hash"] = hashlib.sha256(b"tampered").hexdigest()
        with open(self.baseline, "w") as f:
            json.dump(payload, f)
        code, _, err = self._check("k")
        self.assertEqual(code, 3)
        self.assertIn("CRITICAL", err)

    def test_missing_key_exits_two(self):
        code, _, err = run_cli(["baseline", self.watched, "--out", self.baseline], env_key=None)
        self.assertEqual(code, 2)
        self.assertIn("no signing key", err)

    def test_missing_baseline_file_exits_two(self):
        code, _, err = run_cli(["check", self.watched, "--baseline", self.baseline], env_key="k")
        self.assertEqual(code, 2)
        self.assertIn("no baseline file", err)

    def test_baseline_stored_inside_watched_dir_is_not_self_reported(self):
        inside = os.path.join(self.watched, ".custodian-baseline.json")
        run_cli(["baseline", self.watched, "--out", inside], env_key="k")
        code, out, _ = run_cli(["check", self.watched, "--baseline", inside], env_key="k")
        self.assertEqual(code, 0, out)

    def test_json_output_is_valid_json(self):
        self._baseline()
        with open(os.path.join(self.watched, "new.txt"), "w") as f:
            f.write("x")
        code, out, _ = self._check("k", "--json")
        parsed = json.loads(out)
        self.assertEqual(parsed["added"], ["new.txt"])


if __name__ == "__main__":
    unittest.main()
