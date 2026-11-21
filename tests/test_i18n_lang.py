# -*- coding: utf-8 -*-
"""Regression tests for the interface language selection (v2.13.0).

The bug: cp_shared.i18n was built before CONFIG existed and was never re-bound,
so `lang` in config.json or CRYPTPOUCH_LANG left the interactive menu in
Chinese. These tests pin the fixed behaviour at the process boundary.
"""
import os
import subprocess
import sys
import unittest

PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _env(**overrides):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONNOUSERSITE", None)
    env.pop("CRYPTPOUCH_LANG", None)
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(overrides)
    return env


def _run(code, **overrides):
    p = subprocess.run([sys.executable, "-c", code], cwd=PROJ, env=_env(**overrides),
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=120)
    return p


PROBE = ("import sys; sys.path.insert(0, %r); import cp_shared; "
         "print(cp_shared.i18n.lang + '|' + cp_shared.i18n.t('menu_title'))" % PROJ)


class InterfaceLanguageTest(unittest.TestCase):
    def test_default_is_chinese(self):
        p = _run(PROBE)
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        self.assertEqual(p.stdout.strip(), "zh|主菜单")

    def test_environment_selects_english(self):
        p = _run(PROBE, CRYPTPOUCH_LANG="en")
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        self.assertEqual(p.stdout.strip(), "en|Main Menu")

    def test_unknown_language_falls_back_to_chinese(self):
        p = _run(PROBE, CRYPTPOUCH_LANG="fr")
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        self.assertEqual(p.stdout.strip(), "zh|主菜单")

    def test_menu_entries_render_in_selected_language(self):
        p = subprocess.run([sys.executable, os.path.join(PROJ, "CryptPouch.py")],
                           cwd=PROJ, env=_env(CRYPTPOUCH_LANG="en"),
                           input="0\ny\n", capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=180)
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        self.assertIn("28. XChaCha20-Poly1305 Encrypt (text)", p.stdout)
        self.assertIn("30. High-Security Encrypt (file/dir)", p.stdout)
        self.assertNotIn("高安全模式加密", p.stdout)


if __name__ == "__main__":
    unittest.main()
