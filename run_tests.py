#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run the CryptPouch test suite with per-test listings and colored results.

Zero dependencies: plain ANSI escape codes, applied only when stderr is a real
terminal (or when --color on is passed). Color mapping:

    ok                  green
    FAIL / ERROR        red
    skipped             yellow
    expected failure    cyan
    unexpected success  magenta

Usage:

    python run_tests.py                 # list every test, colored pass/fail markers
    python run_tests.py --color off     # force plain text (default: auto)
"""
import os
import re
import sys
import unittest

_GREEN = "\x1b[32m"
_RED = "\x1b[31m"
_YELLOW = "\x1b[33m"
_CYAN = "\x1b[36m"
_MAGENTA = "\x1b[35m"
_RESET = "\x1b[0m"

# per-test result markers at end of a verbose line
_MARKERS = [
    (r"(?<!\S)expected failure(?=\s*$)", _CYAN),
    (r"(?<!\S)unexpected success(?=\s*$)", _MAGENTA),
    (r"(?<!\S)ok(?=\s*$)", _GREEN),
    (r"(?<!\S)FAIL(?=\s*$)", _RED),
    (r"(?<!\S)ERROR(?=\s*$)", _RED),
    (r"(?<!\S)skipped(?=\s*$)", _YELLOW),
]

# single-letter progress markers in non-verbose mode
_ONE_CHAR = {
    "E": _RED,          # error
    "F": _RED,          # failure
    "s": _YELLOW,       # skipped
    "x": _CYAN,         # expected failure
    "u": _MAGENTA,      # unexpected success
}


class _ColorStream:
    """Wrap a stream; paint unittest result markers with their colors."""

    def __init__(self, stream, enabled):
        self._stream = stream
        self._enabled = enabled

    def write(self, s):
        if self._enabled:
            if re.fullmatch(r"\.+", s):
                s = _GREEN + s + _RESET          # progress dots (passed)
            elif s in _ONE_CHAR:
                s = _ONE_CHAR[s] + s + _RESET     # single-letter progress marker
            else:
                for pat, color in _MARKERS:
                    s = re.sub(pat, color + r"\g<0>" + _RESET, s)
                # summary detail lines and overall outcome
                s = re.sub(r"(?m)^FAIL:", _RED + r"FAIL:" + _RESET, s)
                s = re.sub(r"(?m)^ERROR:", _RED + r"ERROR:" + _RESET, s)
                s = re.sub(r"(?<!\S)FAILED(?=\s|$)", _RED + r"FAILED" + _RESET, s)
                s = re.sub(r"(?<!\S)OK(?=\s*$)", _GREEN + r"OK" + _RESET, s)
        self._stream.write(s)

    def flush(self):
        self._stream.flush()

    def isatty(self):
        return self._stream.isatty()


def _main(argv):
    color = "auto"
    verbosity = 2
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--color" and i + 1 < len(argv):
            color = argv[i + 1]
            i += 2
        elif a == "-q":
            verbosity = 1
            i += 1
        else:
            args.append(a)
            i += 1
    if color == "on":
        enabled = True
    elif color == "off":
        enabled = False
    else:
        enabled = False
        try:
            if os.name == "nt":
                os.system("")  # ask the Windows console to enable VT processing
            enabled = sys.stderr.isatty()
        except Exception:
            enabled = False
    stream = _ColorStream(sys.stderr, enabled)
    # locate tests/ relative to this script, so it works from any directory
    tests_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests")
    suite = unittest.defaultTestLoader.discover(tests_dir)
    result = unittest.TextTestRunner(stream=stream, verbosity=verbosity).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
