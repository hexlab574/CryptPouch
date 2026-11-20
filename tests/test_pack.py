# -*- coding: utf-8 -*-
"""Tests for v2.12.0 features: directory packing and batch manifests.

Run from the CryptPouch package directory:
    python -m unittest discover -s tests -v
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import CryptPouch as cp  # noqa: E402
import cp_pack  # noqa: E402

PWD = "pack-pass-123"


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class PackRoundtripTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cppack_")
        self.src = os.path.join(self.dir, "data")
        os.makedirs(os.path.join(self.src, "nested"))
        with open(os.path.join(self.src, "a.txt"), "w", encoding="utf-8") as f:
            f.write("alpha")
        with open(os.path.join(self.src, "nested", "b.bin"), "wb") as f:
            f.write(b"\x00\x01\x02" * 100)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_pack_encrypt_produces_v4_volume(self):
        out = os.path.join(self.dir, "data.zip.enc")
        res = cp_pack.pack_encrypt(self.src, PWD, out)
        self.assertTrue(os.path.isfile(out))
        self.assertEqual(res["files"], 2)
        with open(out, "rb") as f:
            self.assertEqual(f.read(len(cp.PREFIX_AES_V4)), cp.PREFIX_AES_V4)

    def test_pack_decrypt_roundtrip(self):
        out = os.path.join(self.dir, "data.zip.enc")
        cp_pack.pack_encrypt(self.src, PWD, out)
        target = os.path.join(self.dir, "restored")
        res = cp_pack.pack_decrypt(out, PWD, target)
        self.assertEqual(res["files"], 2)
        with open(os.path.join(target, "a.txt"), encoding="utf-8") as f:
            self.assertEqual(f.read(), "alpha")
        self.assertEqual(_sha(os.path.join(target, "nested", "b.bin")),
                         _sha(os.path.join(self.src, "nested", "b.bin")))

    def test_pack_decrypt_wrong_password_leaves_nothing(self):
        out = os.path.join(self.dir, "data.zip.enc")
        cp_pack.pack_encrypt(self.src, PWD, out)
        target = os.path.join(self.dir, "should_not_exist")
        with self.assertRaises(Exception):
            cp_pack.pack_decrypt(out, "wrong-password-9", target)
        self.assertFalse(os.path.exists(target))

    def test_pack_refuses_existing_output(self):
        out = os.path.join(self.dir, "data.zip.enc")
        cp_pack.pack_encrypt(self.src, PWD, out)
        with self.assertRaises(FileExistsError):
            cp_pack.pack_encrypt(self.src, PWD, out)

    def test_pack_rejects_non_directory(self):
        with self.assertRaises(ValueError):
            cp_pack.pack_encrypt(os.path.join(self.src, "a.txt"), PWD)

    def test_empty_directory_roundtrip(self):
        empty = os.path.join(self.dir, "empty")
        os.makedirs(empty)
        out = os.path.join(self.dir, "empty.zip.enc")
        res = cp_pack.pack_encrypt(empty, PWD, out)
        self.assertEqual(res["files"], 0)
        restored = cp_pack.pack_decrypt(out, PWD, os.path.join(self.dir, "empty_out"))
        self.assertEqual(restored["files"], 0)


class PackSafetyTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cppack_safe_")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_traversal_entries_rejected(self):
        for name in ("../escape.txt", "a/../../escape.txt", "/abs.txt", "C:/abs.txt"):
            with self.assertRaises(ValueError, msg=name):
                cp_pack._safe_entry_name(self.dir, name)

    def test_normal_entries_accepted(self):
        target = cp_pack._safe_entry_name(self.dir, "sub/dir/file.txt")
        self.assertTrue(target.startswith(os.path.abspath(self.dir)))

    def test_crafted_archive_never_escapes(self):
        evil = os.path.join(self.dir, "evil.zip")
        with zipfile.ZipFile(evil, "w") as zf:
            zf.writestr("../../escaped.txt", "x")
        enc = os.path.join(self.dir, "evil.zip.enc")
        cp.encrypt_file(evil, enc, PWD)
        with self.assertRaises(ValueError):
            cp_pack.pack_decrypt(enc, PWD, os.path.join(self.dir, "out"))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "escaped.txt")))
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.dir), "escaped.txt")))


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cpmanifest_")
        self.batch = os.path.join(self.dir, "batch")
        os.makedirs(self.batch)
        for name in ("one.txt", "two.txt"):
            with open(os.path.join(self.batch, name), "w", encoding="utf-8") as f:
                f.write("payload-" + name)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_batch_reports_items(self):
        res = cp.batch_encrypt(self.batch, PWD)
        self.assertEqual(len(res["items"]), 2)
        self.assertTrue(all(item["status"] == "encrypted" for item in res["items"]))
        self.assertTrue(all(os.path.isfile(item["output"]) for item in res["items"]))

    def test_manifest_hashes_match_files(self):
        res = cp.batch_encrypt(self.batch, PWD)
        report = cp_pack.build_manifest(res["items"], "encrypt", tool_version="test")
        self.assertEqual(report["summary"]["total"], 2)
        self.assertEqual(report["summary"]["ok"], 2)
        for item in report["items"]:
            self.assertEqual(item["sha256"], _sha(item["output"]))
            self.assertGreater(item["size"], 0)

    def test_manifest_failure_rows_keep_errors(self):
        res = cp.batch_encrypt(self.batch, PWD)
        items = [dict(item) for item in res["items"]]
        items[0]["status"] = "failed"
        items[0]["error"] = "boom"
        items[0]["output"] = os.path.join(self.dir, "missing.enc")
        report = cp_pack.build_manifest(items, "encrypt", tool_version="test")
        self.assertEqual(report["summary"]["failed"], 1)
        self.assertEqual(report["items"][0]["error"], "boom")
        self.assertIsNone(report["items"][0]["sha256"])

    def test_manifest_file_is_utf8_json(self):
        res = cp.batch_encrypt(self.batch, PWD)
        report = cp_pack.build_manifest(res["items"], "encrypt", tool_version="test")
        path = cp_pack.write_manifest(report, os.path.join(self.dir, "sub", "report.json"))
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
        self.assertEqual(loaded["operation"], "encrypt")
        self.assertEqual(len(loaded["items"]), 2)


class CliAutoRoutingTest(unittest.TestCase):
    """`-e <existing path>` must encrypt the file, not the string."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cpcli_")
        self.file = os.path.join(self.dir, "notes.txt")
        with open(self.file, "w", encoding="utf-8") as f:
            f.write("cli body")
        self.script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                   "CryptPouch.py")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _run(self, args):
        return subprocess.run([sys.executable, self.script] + args, capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              cwd=os.path.dirname(self.script), timeout=120)

    def test_encrypt_path_without_f_flag_writes_enc_file(self):
        p = self._run(["-e", self.file, "-p", PWD, "--lang", "en"])
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue(os.path.isfile(self.file + ".enc"))
        self.assertIn("file mode", (p.stdout + p.stderr).lower())

    def test_text_output_flag_writes_file(self):
        cipher = os.path.join(self.dir, "cipher.txt")
        p = self._run(["-e", "hello text", "-p", PWD, "-o", cipher, "--lang", "en"])
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue(os.path.isfile(cipher))
        with open(cipher, encoding="utf-8") as f:
            body = f.read().strip()
        self.assertTrue(body)
        # and the written ciphertext must decrypt back
        out = os.path.join(self.dir, "back.txt")
        p2 = self._run(["-d", body, "-p", PWD, "-o", out, "--lang", "en"])
        self.assertEqual(p2.returncode, 0, p2.stdout + p2.stderr)
        with open(out, encoding="utf-8") as f:
            self.assertEqual(f.read().strip(), "hello text")


if __name__ == "__main__":
    unittest.main()
