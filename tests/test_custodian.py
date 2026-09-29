import os
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from custodian.hashing import hash_file, sign, verify_signature
from custodian.baseline import (
    build_manifest, diff_manifests, save_signed_baseline,
    load_and_verify_baseline, BaselineTamperedError,
)


class TestHashing(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_hash_is_consistent(self):
        path = os.path.join(self.tmpdir, "a.txt")
        with open(path, "w") as f:
            f.write("hello world")
        self.assertEqual(hash_file(path), hash_file(path))

    def test_different_content_different_hash(self):
        path_a = os.path.join(self.tmpdir, "a.txt")
        path_b = os.path.join(self.tmpdir, "b.txt")
        with open(path_a, "w") as f:
            f.write("hello world")
        with open(path_b, "w") as f:
            f.write("hello world!")
        self.assertNotEqual(hash_file(path_a), hash_file(path_b))

    def test_sign_and_verify_roundtrip(self):
        data = b"some manifest content"
        signature = sign(data, "correct-key")
        self.assertTrue(verify_signature(data, "correct-key", signature))

    def test_verify_fails_with_wrong_key(self):
        data = b"some manifest content"
        signature = sign(data, "correct-key")
        self.assertFalse(verify_signature(data, "wrong-key", signature))

    def test_verify_fails_if_data_changed(self):
        original = b"some manifest content"
        signature = sign(original, "correct-key")
        tampered = b"some manifest CONTENT"
        self.assertFalse(verify_signature(tampered, "correct-key", signature))


class TestBuildManifest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write(self, rel_path, content):
        full = os.path.join(self.tmpdir, rel_path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
        return full

    def test_finds_all_files(self):
        self._write("a.txt", "aaa")
        self._write("sub/b.txt", "bbb")
        manifest = build_manifest(self.tmpdir)
        self.assertIn("a.txt", manifest)
        self.assertIn(os.path.join("sub", "b.txt"), manifest)

    def test_excludes_default_dirs(self):
        self._write(".git/HEAD", "ref: refs/heads/main")
        self._write("node_modules/pkg/index.js", "module.exports = {}")
        self._write("real_file.py", "print('hi')")
        manifest = build_manifest(self.tmpdir)
        self.assertEqual(list(manifest.keys()), ["real_file.py"])

    def test_excludes_the_baseline_file_itself(self):
        self._write("a.txt", "aaa")
        baseline_path = os.path.join(self.tmpdir, "baseline.json")
        with open(baseline_path, "w") as f:
            f.write("{}")
        manifest = build_manifest(self.tmpdir, exclude_paths={baseline_path})
        self.assertNotIn("baseline.json", manifest)
        self.assertIn("a.txt", manifest)

    def test_records_mode_bits(self):
        path = self._write("script.sh", "#!/bin/sh\necho hi")
        os.chmod(path, 0o644)
        manifest = build_manifest(self.tmpdir)
        self.assertEqual(manifest["script.sh"]["mode"], 0o644)


class TestDiffManifests(unittest.TestCase):
    def test_detects_modified_file(self):
        baseline = {"a.txt": {"hash": "aaa", "size": 3, "mode": 0o644}}
        current = {"a.txt": {"hash": "bbb", "size": 3, "mode": 0o644}}
        diff = diff_manifests(baseline, current)
        self.assertEqual(diff["modified"], ["a.txt"])
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])

    def test_detects_added_file(self):
        baseline = {}
        current = {"new.txt": {"hash": "aaa", "size": 3, "mode": 0o644}}
        diff = diff_manifests(baseline, current)
        self.assertEqual(diff["added"], ["new.txt"])

    def test_detects_removed_file(self):
        baseline = {"gone.txt": {"hash": "aaa", "size": 3, "mode": 0o644}}
        current = {}
        diff = diff_manifests(baseline, current)
        self.assertEqual(diff["removed"], ["gone.txt"])

    def test_no_changes_reports_nothing(self):
        manifest = {"a.txt": {"hash": "aaa", "size": 3, "mode": 0o644}}
        diff = diff_manifests(manifest, dict(manifest))
        self.assertEqual(diff["modified"], [])
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["permission_changes"], [])

    def test_detects_permission_change_on_unmodified_content(self):
        baseline = {"a.txt": {"hash": "aaa", "size": 3, "mode": 0o644}}
        current = {"a.txt": {"hash": "aaa", "size": 3, "mode": 0o777}}
        diff = diff_manifests(baseline, current)
        self.assertEqual(diff["modified"], [])
        self.assertEqual(len(diff["permission_changes"]), 1)
        self.assertEqual(diff["permission_changes"][0]["path"], "a.txt")

    def test_flags_newly_world_writable(self):
        baseline = {"a.txt": {"hash": "aaa", "size": 3, "mode": 0o644}}
        current = {"a.txt": {"hash": "aaa", "size": 3, "mode": 0o646}}  # added world-write bit
        diff = diff_manifests(baseline, current)
        self.assertIn("a.txt", diff["newly_world_writable"])

    def test_does_not_flag_already_world_writable_as_new(self):
        baseline = {"a.txt": {"hash": "aaa", "size": 3, "mode": 0o646}}
        current = {"a.txt": {"hash": "aaa", "size": 3, "mode": 0o646}}
        diff = diff_manifests(baseline, current)
        self.assertEqual(diff["newly_world_writable"], [])


class TestSignedBaseline(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.baseline_path = os.path.join(self.tmpdir, "baseline.json")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_roundtrip_with_correct_key(self):
        manifest = {"a.txt": {"hash": "aaa", "size": 3, "mode": 0o644}}
        save_signed_baseline(self.baseline_path, manifest, "my-key")
        loaded = load_and_verify_baseline(self.baseline_path, "my-key")
        self.assertEqual(loaded, manifest)

    def test_wrong_key_raises_tampered_error(self):
        manifest = {"a.txt": {"hash": "aaa", "size": 3, "mode": 0o644}}
        save_signed_baseline(self.baseline_path, manifest, "my-key")
        with self.assertRaises(BaselineTamperedError):
            load_and_verify_baseline(self.baseline_path, "wrong-key")

    def test_edited_baseline_file_raises_tampered_error(self):
        """
        The core defense this tool adds over a naive baseline file: if an
        attacker (or anyone) modifies the baseline JSON directly, to hide
        evidence of tampering with a monitored file, the signature check
        must catch that, even without knowing what the "correct" content
        should have been.
        """
        manifest = {"a.txt": {"hash": "aaa", "size": 3, "mode": 0o644}}
        save_signed_baseline(self.baseline_path, manifest, "my-key")

        # Simulate an attacker editing the baseline file directly to
        # match a file they've since modified, without knowing the key.
        import json
        with open(self.baseline_path) as f:
            payload = json.load(f)
        payload["manifest"]["a.txt"]["hash"] = "attacker-controlled-hash"
        with open(self.baseline_path, "w") as f:
            json.dump(payload, f)

        with self.assertRaises(BaselineTamperedError):
            load_and_verify_baseline(self.baseline_path, "my-key")


if __name__ == "__main__":
    unittest.main()
