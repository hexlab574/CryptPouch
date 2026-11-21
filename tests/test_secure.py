# -*- coding: utf-8 -*-
"""Tests for v2.13.0 features: XChaCha20-Poly1305 ($XS1$) and high-security mode.

Run from the CryptPouch package directory:
    python -m unittest discover -s tests -v
"""
import base64
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import CryptPouch as cp  # noqa: E402
import cp_files  # noqa: E402
import cp_pack  # noqa: E402
import cryptpouch_api as api  # noqa: E402

PWD = "xchacha-pass-123"
PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class XChaCha20TextTest(unittest.TestCase):
    def test_roundtrip_standard_cost(self):
        tool = cp.XChaCha20Poly1305Tool(PWD)
        ct = tool.encrypt("hello 世界")
        self.assertEqual(tool.decrypt(ct), "hello 世界")

    def test_roundtrip_high_security_cost(self):
        tool = cp.XChaCha20Poly1305Tool(PWD, secure=True)
        ct = tool.encrypt("secure text")
        self.assertEqual(tool.decrypt(ct), "secure text")

    def test_header_records_high_security_params(self):
        ct = cp.XChaCha20Poly1305Tool(PWD, secure=True).encrypt("params")
        raw = cp._decode_pack_b64(ct)
        self.assertEqual(raw[:5], cp.PREFIX_XCHACHA20)
        params = cp.decode_kdf_header(raw[5:11])
        self.assertEqual(params, cp.HIGH_SECURITY_KDF)

    def test_auto_detect_routes_xs1(self):
        for secure in (False, True):
            ct = cp.XChaCha20Poly1305Tool(PWD, secure=secure).encrypt("auto")
            self.assertEqual(cp.try_text_decrypt(ct, PWD), "auto")

    def test_wrong_password_rejected(self):
        ct = cp.XChaCha20Poly1305Tool(PWD).encrypt("secret")
        with self.assertRaises(cp.PasswordError):
            cp.XChaCha20Poly1305Tool("wrong-pass-xyz").decrypt(ct)

    def test_truncated_payload_rejected(self):
        ct = cp.XChaCha20Poly1305Tool(PWD).encrypt("secret")
        raw = cp._decode_pack_b64(ct)
        broken = base64.b64encode(raw[:10]).decode("ascii")
        with self.assertRaises(cp.CipherCorruptedError):
            cp.XChaCha20Poly1305Tool(PWD).decrypt(broken)


class XChaCha20FileTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cpxs_")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _roundtrip(self, payload, secure):
        src = os.path.join(self.dir, "plain.bin")
        enc = src + ".enc"
        out = os.path.join(self.dir, "plain.out")
        with open(src, "wb") as f:
            f.write(payload)
        cp.encrypt_file(src, enc, PWD, cipher="xchacha20", secure=secure)
        with open(enc, "rb") as f:
            self.assertEqual(f.read(5), cp.PREFIX_XCHACHA20)
        cp.decrypt_file(enc, out, PWD)   # cost comes from the header, no flag needed
        with open(out, "rb") as f:
            self.assertEqual(f.read(), payload)
        return enc

    def test_roundtrip_standard_cost(self):
        self._roundtrip(b"x" * (1 << 20), secure=False)

    def test_roundtrip_high_security_self_describing(self):
        enc = self._roundtrip(b"high security payload\n" * 100, secure=True)
        with open(enc, "rb") as f:
            params = cp.decode_kdf_header(f.read(11)[5:11])
        self.assertEqual(params, cp.HIGH_SECURITY_KDF)

    def test_wrong_password_rejected(self):
        src = os.path.join(self.dir, "a.txt")
        enc = src + ".enc"
        with open(src, "wb") as f:
            f.write(b"wrong password check")
        cp.encrypt_file(src, enc, PWD, cipher="xchacha20")
        with self.assertRaises(cp.PasswordError):
            cp.decrypt_file(enc, os.path.join(self.dir, "a.out"), "wrong-pass-xyz")

    def test_out_of_range_kdf_header_rejected(self):
        src = os.path.join(self.dir, "b.txt")
        enc = src + ".enc"
        with open(src, "wb") as f:
            f.write(b"header tamper check")
        cp.encrypt_file(src, enc, PWD, cipher="xchacha20")
        with open(enc, "r+b") as f:
            f.seek(5)
            f.write((cp.KDF_MEMORY_MAX_KIB + 1024).to_bytes(4, "big"))
        with self.assertRaises(cp.CipherCorruptedError):
            cp.decrypt_file(enc, os.path.join(self.dir, "b.out"), PWD)

    def test_zero_time_cost_rejected(self):
        src = os.path.join(self.dir, "c.txt")
        enc = src + ".enc"
        with open(src, "wb") as f:
            f.write(b"zero time cost")
        cp.encrypt_file(src, enc, PWD, cipher="xchacha20")
        with open(enc, "r+b") as f:
            f.seek(9)  # memory_kib(4) then time_cost(1) => offset 9
            f.write(b"\x00")
        with self.assertRaises(cp.CipherCorruptedError):
            cp.decrypt_file(enc, os.path.join(self.dir, "c.out"), PWD)

    def test_aes_gcm_format_unaffected(self):
        src = os.path.join(self.dir, "d.txt")
        enc = src + ".enc"
        out = os.path.join(self.dir, "d.out")
        with open(src, "wb") as f:
            f.write(b"legacy format payload")
        cp.encrypt_file(src, enc, PWD)          # default AES-256-GCM
        with open(enc, "rb") as f:
            self.assertEqual(f.read(5), cp.PREFIX_AES_V4)
        cp.decrypt_file(enc, out, PWD)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), b"legacy format payload")


class XChaCha20BatchAndPackTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cpxsb_")
        self.src = os.path.join(self.dir, "data")
        os.makedirs(os.path.join(self.src, "nested"))
        for name, text in (("a.txt", "alpha"), ("nested/b.txt", "beta")):
            with open(os.path.join(self.src, name), "w", encoding="utf-8") as f:
                f.write(text)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_batch_encrypt_secure(self):
        res = cp.batch_encrypt(self.src, PWD, cipher="xchacha20", secure=True)
        self.assertEqual(len(res["encrypted"]), 2)
        for path in res["encrypted"]:
            with open(path, "rb") as f:
                self.assertEqual(f.read(5), cp.PREFIX_XCHACHA20)

    def test_pack_encrypt_secure_roundtrip(self):
        out = os.path.join(self.dir, "data.zip.enc")
        res = cp_pack.pack_encrypt(self.src, PWD, out, cipher="xchacha20", secure=True)
        self.assertEqual(res["files"], 2)
        with open(out, "rb") as f:
            self.assertEqual(f.read(5), cp.PREFIX_XCHACHA20)
        target = os.path.join(self.dir, "restored")
        res2 = cp_pack.pack_decrypt(out, PWD, target)
        self.assertEqual(res2["files"], 2)
        with open(os.path.join(target, "nested", "b.txt"), encoding="utf-8") as f:
            self.assertEqual(f.read(), "beta")


class XChaCha20ApiTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cpxsapi_")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_encrypt_text_xchacha20(self):
        ct = api.encrypt_text("api text", PWD, mode="xchacha20", secure=True)
        self.assertEqual(api.decrypt_text(ct, PWD), "api text")
        self.assertEqual(cp._decode_pack_b64(ct)[:5], cp.PREFIX_XCHACHA20)

    def test_encrypt_file_xchacha20(self):
        src = os.path.join(self.dir, "api.txt")
        with open(src, "wb") as f:
            f.write(b"api file payload" * 50)
        out = api.encrypt_file(src, PWD, secure=True)
        with open(out, "rb") as f:
            self.assertEqual(f.read(5), cp.PREFIX_XCHACHA20)
        back = os.path.join(self.dir, "api.out")
        api.decrypt_file(out, PWD, back)
        with open(back, "rb") as f:
            self.assertEqual(f.read(), b"api file payload" * 50)

    def test_unknown_mode_rejected(self):
        with self.assertRaises(ValueError):
            api.encrypt_text("x", PWD, mode="sm4")


class XChaCha20CliTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cpxscli_")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _run(self, args, expect_rc=0):
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        p = subprocess.run([sys.executable, os.path.join(PROJ, "CryptPouch.py")] + args,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", env=env, timeout=300)
        self.assertEqual(p.returncode, expect_rc,
                         "rc=%s out=%s err=%s" % (p.returncode, p.stdout[-400:], p.stderr[-400:]))
        return p

    def test_secure_file_encrypt_and_decrypt(self):
        src = os.path.join(self.dir, "cli.txt")
        with open(src, "wb") as f:
            f.write(b"cli secure payload " * 40)
        enc = src + ".enc"
        self._run(["-e", src, "-p", PWD, "--secure", "-o", enc])
        with open(enc, "rb") as f:
            self.assertEqual(f.read(5), cp.PREFIX_XCHACHA20)
        out = os.path.join(self.dir, "cli.out")
        self._run(["-d", enc, "-p", PWD, "-o", out])
        with open(out, "rb") as f:
            self.assertEqual(f.read(), b"cli secure payload " * 40)

    def test_secure_text_payload(self):
        out = os.path.join(self.dir, "text.enc")
        self._run(["-e", "cli secure text", "-p", PWD, "--secure", "-o", out])
        with open(out, encoding="utf-8") as f:
            ct = f.read().strip()
        self.assertEqual(cp._decode_pack_b64(ct)[:5], cp.PREFIX_XCHACHA20)
        self.assertEqual(api.decrypt_text(ct, PWD), "cli secure text")

    def test_cipher_modes_include_xchacha20(self):
        self.assertIn("xchacha20", cp.CIPHER_MODES)


if __name__ == "__main__":
    unittest.main()
