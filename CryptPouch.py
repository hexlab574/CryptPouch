#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AES256 Encryption Toolbox
Version: 2.9.0
License: MIT
Note: For learning, research and personal local use only.

v2.9.0 additions:
- Password strength extensions: optional external weak-password dictionary
  (validated path, size cap, fail-safe skip), whole "word + year" detection
  (1900-2099), and sliding-window QWERTY keyboard patterns (row/column/diagonal)
- set_config(): merge, validate, atomically write ~/.cryptpouch/config.json
  (never overrides CLI or environment priority); reload=True refreshes live state
- ANSI color output for warnings (yellow) and errors (red) with a color config
  switch (auto/on/off), zero third-party dependencies
- run_tests.py: zero-dependency test runner with green pass markers

v2.8.0 additions:
- User configuration via ~/.cryptpouch/config.json and CRYPTOUCH_* environment variables
- ChaCha20-Poly1305 AEAD support ($CC1$, Argon2id-derived key)
- One-step key rotation / re-encryption (legacy v2 -> v3/ChaCha20, or password change)
- Batch directory/file encryption and decryption with glob filters
- Memory hygiene: derived keys are zeroed in place; password comparisons use hmac.compare_digest
  (note: Python str objects are immutable and cannot be explicitly erased)
"""

import argparse
import base64
import fnmatch
import getpass
import hashlib
import hmac
import importlib.util
import json
import os
import secrets
import string
import subprocess
import sys
import tempfile
import time
from typing import Optional, Tuple, List


# ====================== Console encoding compatibility ======================
# Fix: the Windows Chinese locale defaults to the GBK code page, which cannot encode the glyphs
# used in output, causing print to raise UnicodeEncodeError and crash after language selection.

def _setup_console_encoding():
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    # Switch the console code page to UTF-8 (65001) on Windows so Chinese text and glyphs display correctly.
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleCP(65001)
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass


_setup_console_encoding()


# ====================== Bilingual prompts ======================

LANG = {
    "zh": {
        "welcome": "你好呀～欢迎使用 AES256 加密工具箱 ",
        "usage_tip": "这个工具可以帮你做文本加密、文件加密、哈希、RSA 和二维码。",
        "legal_tip": "注意：仅供学习研究与个人本地使用，不要用于非法用途",
        "select_lang": "请选择语言：",
        "lang_zh": "1. 中文",
        "lang_en": "2. English",
        "invalid_lang": "选择无效，默认使用中文。",
        "core_deps_missing": "检测到缺少核心依赖，需要安装后才能继续。",
        "optional_deps_missing": "有一些可选依赖缺失，相关功能可能无法使用。",
        "missing_list": "缺失列表：",
        "install_cmd_global": "官方安装命令：",
        "install_cmd_cn": "国内镜像安装命令：",
        "ask_install": "需要我帮你自动安装吗？输入 y 确认，n 取消：",
        "installing": "好的，正在尝试安装，请稍等。",
        "install_success": "安装完成啦！程序即将重启。",
        "install_fail": "自动安装失败了，请手动复制上面的命令安装。",
        "install_cancel": "好的，已取消安装。部分功能可能无法使用。",
        "menu_title": "主菜单",
        "input_too_long": "输入内容过长（上限 {max} 字符）。",
        "attempts_left": "密码不正确，还可尝试 {left} 次。",
        "attempts_exceeded": "多次尝试失败，已返回主菜单。",
        "input_choice": "请输入选项：",
        "invalid_choice": "输入无效，请输入菜单里的数字。",
        "encrypt_pwd": "请输入加密密码：",
        "confirm_pwd": "请再次输入密码确认：",
        "pwd_mismatch": "两次输入的密码不一致，请重新输入",
        "pwd_too_long": "密码长度超过上限（最大 {max} 字符），请缩短后重试",
        "decrypt_pwd": "请输入解密密码：",
        "input_plain": "请输入明文：",
        "input_cipher": "请输入密文：",
        "file_path": "请输入文件路径：",
        "file_not_exist": "文件不存在",
        "success": "完成啦 ",
        "fail": "失败了",
        "cancel": "已取消。",
        "ctrl_c_hint": "已取消当前操作。再次按 Ctrl+C 可退出程序",
        "mem_error": "内存不足，程序即将退出",
        "qr_too_long": "二维码内容过长，无法生成",
        "err_rsa_key_strength": "RSA 密钥强度验证失败",
        "exit_confirm": "确认要退出吗？(y/n)：",
        "bye": "拜拜啦，下次再见～",
        "copy_done": "已复制到剪贴板。",
        "copy_fail": "剪贴板复制失败了，可以手动记录。",
        "target_exists": "目标文件已存在，是否覆盖？(y/n)：",
        "kept_original": "已保留原文件，解密产物保存为：",
        "alg_prompt": "算法（默认 sha256）：",
        "len_prompt": "密码长度（默认 16）：",
        "pwd_input_prompt": "请输入要检测的密码：",
        "strength_label": "密码强度：{level}",
        "strength_strong": "强",
        "strength_medium": "中",
        "strength_weak": "弱",
        "tip_len_short": "建议长度不少于 8 位",
        "tip_char_types": "建议包含大小写、数字、特殊符号中至少 3 种",
        "tip_weak_common": "该密码属于常见弱密码，极易被破解",
        "tip_keyboard": "避免使用键盘连续键位（如 qwerty）",
        "tip_sequence": "避免使用纯数字、重复字符或连续递增/递减序列",
        "tip_year": "避免使用'单词+年份'组合（如 Summer2024）",
        "dict_missing": "弱密码字典不存在：{path}",
        "dict_too_large": "弱密码字典过大（上限 {limit} 字节），已跳过",
        "dict_skip": "弱密码字典加载失败，已跳过该检查：{reason}",
        "cfg_unknown_key": "未知配置键：{k}",
        "cfg_invalid_value": "配置值无效：{k}={v}",
        "rsa_gen_keys": "正在生成 RSA 密钥对...",
        "rsa_bits_prompt": "密钥位数（回车默认 2048，可输 3072/4096）：",
        "rsa_bits_invalid": "仅支持 2048/3072/4096 位",
        "rsa_protect_prompt": "是否为私钥设置密码保护？(y/n)：",
        "rsa_enter_passphrase": "请输入私钥保护密码：",
        "rsa_private_label": "私钥：{path}",
        "rsa_public_label": "公钥：{path}",
        "rsa_pub_path_prompt": "请输入公钥文件路径：",
        "rsa_enter_text": "请输入要加密的文本：",
        "rsa_pri_path_prompt": "请输入私钥文件路径：",
        "rsa_enter_cipher": "请输入 RSA 密文：",
        "rsa_has_passphrase": "私钥是否设置了密码？(y/n)：",
        "file_encrypted_to": "已加密到 {path}",
        "file_decrypted_to": "已解密到 {path}",
        "qr_content_prompt": "请输入二维码内容：",
        "qr_preview": "二维码预览：",
        "qr_save_prompt": "是否保存为图片？(y/n)：",
        "qr_filename_prompt": "请输入保存文件名：",
        "qr_missing_pkg": "请先安装 qrcode 和 pillow 库",
        "zb_missing_pkg": "请先安装 pyzbar 和 pillow 库",
        "qr_no_content": "未识别到二维码内容",
        "qr_saved_to": "二维码已保存到 {path}",
        "auto_encoding": "已自动检测编码：{enc}",
        "auto_b64_detected": "识别为可读 Base64 文本",
        "legacy_decrypt_hint": "已按兼容参数解密：{iters} 次迭代，{hash}",
        "auto_try_aes": "尝试 AES 解密...",
        "auto_force_aes": "是否尝试 AES 解密？(y/n)：",
        "auto_gcm_ok": "AES-GCM 解密成功",
        "auto_cbc_ok": "AES-CBC 解密成功",
        "cli_file_encrypted": "文件加密完成",
        "cli_file_decrypted": "文件解密完成，已保存到 {path}",
        "cli_output_exists": "输出文件已存在，请使用 -o 指定输出路径。",
        "err_pwd_or_tamper": "密码错误或密文已被篡改",
        "err_pwd_or_file_tamper": "密码错误或文件已被篡改",
        "err_b64_corrupted": "Base64 数据损坏",
        "err_len_invalid": "密文长度非法",
        "err_bad_path": "路径包含非法字符",
        "ac2_legacy_hint": "该密文使用旧版同密钥方案加密，建议用当前版本重新加密后保存",
        "err_file_format": "不支持的文件格式",
        "err_rsa_text_long": "RSA 文本过长，2048 位密钥最多加密约 190 字节",
        "err_hash_alg": "不支持的哈希算法",
        "cli_desc": "AES256 综合加密工具箱命令行模式",
        "cli_e_help": "加密文本或文件",
        "cli_d_help": "解密文本或文件",
        "cli_p_help": "密码（注意：会暴露于进程列表，敏感场景建议交互输入或 --password-file）",
        "cli_p_warn": "警告：密码经 -p 传入会明文出现在进程列表中，建议改用 --password-file 或交互输入",
        "cli_password_file_help": "从文件读取密码（避免进程列表暴露）",
        "cli_f_help": "文件模式",
        "cli_o_help": "输出文件路径",
        "cli_hash_help": "计算文件哈希，如 sha256",
        "cli_lang_help": "语言",
        "analyze_input": "请输入要识别的文本：",
        "analyze_title": "分析结果：",
        "analyze_encoding": "编码：{enc}",
        "analyze_type_plain": "类型：普通文本",
        "analyze_type_b64": "类型：Base64 编码文本",
        "analyze_type_aes_gcm": "类型：AES-GCM 加密密文（CryptPouch 格式）",
        "analyze_type_aes_cbc": "类型：AES-CBC 加密密文（CryptPouch 格式）",
        "analyze_type_binary": "类型：无法直接识别的二进制或加密数据",
        "analyze_type_aes_legacy": "类型：疑似 AES 加密密文（旧版格式，无版本标记）",
        "analyze_try_decrypt": "是否尝试解密？(y/n)：",
        "analyze_type_chacha20": "类型：ChaCha20-Poly1305 加密密文（CryptPouch 格式）",
        "auto_chacha_ok": "ChaCha20-Poly1305 解密成功",
        "err_cipher_mode": "不支持的加密算法（gcm/cbc/chacha20）",
        "cli_cipher_help": "加密算法：gcm/cbc/chacha20（默认 gcm）",
        "reencrypt_old_pwd": "请输入旧密码：",
        "reencrypt_new_pwd": "请输入新密码：",
        "reencrypt_mode_prompt": "目标格式（gcm/cbc/chacha20，回车默认 gcm）：",
        "reencrypt_done": "密钥轮转完成",
        "reencrypt_output": "已保存到 {path}",
        "batch_path_prompt": "请输入目录或文件路径：",
        "batch_pattern_prompt": "文件类型过滤（逗号分隔，如 *.txt,*.md，回车=全部）：",
        "batch_encrypted_n": "加密完成：{n} 个文件",
        "batch_decrypted_n": "解密完成：{n} 个文件",
        "batch_overwrite_hint": "批量解密将覆盖同名文件，请确认后再继续。",
    },
    "en": {
        "welcome": "Hi there! Welcome to the AES256 Crypto Toolkit ",
        "usage_tip": "It supports text encryption, file encryption, hashing, RSA, and QR codes.",
        "legal_tip": "Note: For learning and personal local use only. Do not use for illegal purposes.",
        "select_lang": "Please select language:",
        "lang_zh": "1. 中文",
        "lang_en": "2. English",
        "invalid_lang": "Invalid choice. English selected by default.",
        "core_deps_missing": "Core dependencies are missing. Installation is required to continue.",
        "optional_deps_missing": "Some optional dependencies are missing. Related features may be disabled.",
        "missing_list": "Missing packages:",
        "install_cmd_global": "Global install command:",
        "install_cmd_cn": "Chinese mirror install command:",
        "ask_install": "Should I try to install them automatically? Enter y to confirm, n to cancel:",
        "installing": "OK, installing now, please wait.",
        "install_success": "Installation successful! The program will restart now.",
        "install_fail": "Auto install failed. Please copy the commands above and install manually.",
        "install_cancel": "OK, installation cancelled. Some features may not be available.",
        "menu_title": "Main Menu",
        "input_too_long": "Input too long (limit {max} characters).",
        "attempts_left": "Wrong password; {left} attempt(s) left.",
        "attempts_exceeded": "Too many failed attempts; returning to the menu.",
        "input_choice": "Enter your choice:",
        "invalid_choice": "Invalid input. Please enter a number from the menu.",
        "encrypt_pwd": "Enter encryption password:",
        "confirm_pwd": "Confirm password: ",
        "pwd_mismatch": "Passwords do not match, please try again",
        "pwd_too_long": "Password exceeds the maximum length ({max} chars). Please shorten it.",
        "decrypt_pwd": "Enter decryption password:",
        "input_plain": "Enter plaintext:",
        "input_cipher": "Enter ciphertext:",
        "file_path": "Enter file path:",
        "file_not_exist": "File does not exist.",
        "success": "Done ",
        "fail": "Failed",
        "cancel": "Cancelled.",
        "ctrl_c_hint": "Operation cancelled. Press Ctrl+C again to exit.",
        "mem_error": "Out of memory, the program will exit now",
        "qr_too_long": "QR content too long to generate",
        "err_rsa_key_strength": "RSA key strength check failed",
        "exit_confirm": "Confirm exit? (y/n):",
        "bye": "Bye! See you next time.",
        "copy_done": "Copied to clipboard.",
        "copy_fail": "Clipboard copy failed. Please save it manually.",
        "target_exists": "Target file already exists. Overwrite? (y/n):",
        "kept_original": "Original file kept. Decrypted to:",
        "alg_prompt": "Algorithm (default sha256): ",
        "len_prompt": "Password length (default 16): ",
        "pwd_input_prompt": "Enter password to check: ",
        "strength_label": "Password strength: {level}",
        "strength_strong": "Strong",
        "strength_medium": "Medium",
        "strength_weak": "Weak",
        "tip_len_short": "Recommended length: at least 8",
        "tip_char_types": "Use at least 3 of lowercase, uppercase, digits, symbols",
        "tip_weak_common": "This is a common weak password",
        "tip_keyboard": "Avoid keyboard patterns (e.g. qwerty)",
        "tip_sequence": "Avoid pure digits, repeated characters, or sequential patterns",
        "tip_year": "Avoid word+year patterns (e.g. Summer2024)",
        "dict_missing": "Weak-password dictionary not found: {path}",
        "dict_too_large": "Weak-password dictionary too large (limit {limit} bytes); check skipped",
        "dict_skip": "Weak-password dictionary unavailable; check skipped: {reason}",
        "cfg_unknown_key": "Unknown config key: {k}",
        "cfg_invalid_value": "Invalid config value: {k}={v}",
        "rsa_gen_keys": "Generating RSA key pair...",
        "rsa_bits_prompt": "Key size in bits (Enter for 2048, or 3072/4096): ",
        "rsa_bits_invalid": "Only 2048/3072/4096 bits are supported",
        "rsa_protect_prompt": "Protect private key with password? (y/n): ",
        "rsa_enter_passphrase": "Enter private key protection password: ",
        "rsa_private_label": "Private key: {path}",
        "rsa_public_label": "Public key: {path}",
        "rsa_pub_path_prompt": "Enter public key file path: ",
        "rsa_enter_text": "Enter text to encrypt: ",
        "rsa_pri_path_prompt": "Enter private key file path: ",
        "rsa_enter_cipher": "Enter RSA ciphertext: ",
        "rsa_has_passphrase": "Private key has a password? (y/n): ",
        "file_encrypted_to": "Encrypted to {path}",
        "file_decrypted_to": "Decrypted to {path}",
        "qr_content_prompt": "Enter QR content: ",
        "qr_preview": "QR code preview:",
        "qr_save_prompt": "Save as image? (y/n): ",
        "qr_filename_prompt": "Enter save filename: ",
        "qr_missing_pkg": "Please install qrcode and pillow first",
        "zb_missing_pkg": "Please install pyzbar and pillow first",
        "qr_no_content": "No QR code detected",
        "qr_saved_to": "QR code saved to {path}",
        "auto_encoding": "Auto-detected encoding: {enc}",
        "auto_b64_detected": "Readable Base64 detected",
        "legacy_decrypt_hint": "Decrypted with legacy parameters: {iters} iterations, {hash}",
        "auto_try_aes": "Trying AES decryption...",
        "auto_force_aes": "Try AES decryption? (y/n): ",
        "auto_gcm_ok": "AES-GCM decrypted",
        "auto_cbc_ok": "AES-CBC decrypted",
        "cli_file_encrypted": "File encrypted",
        "cli_file_decrypted": "File decrypted to {path}",
        "cli_output_exists": "Output file already exists. Use -o to specify an output path.",
        "err_pwd_or_tamper": "Wrong password or ciphertext tampered",
        "err_pwd_or_file_tamper": "Wrong password or file tampered",
        "err_b64_corrupted": "Base64 data corrupted",
        "err_len_invalid": "Invalid ciphertext length",
        "err_bad_path": "Path contains illegal characters",
        "ac2_legacy_hint": "This ciphertext uses the legacy same-key scheme. Re-encrypt with the current version to harden it.",
        "err_file_format": "Unsupported file format",
        "err_rsa_text_long": "RSA plaintext too long (max ~190 bytes with a 2048-bit key)",
        "err_hash_alg": "Unsupported hash algorithm",
        "cli_desc": "AES256 Crypto Toolkit command line mode",
        "cli_e_help": "Encrypt text or file",
        "cli_d_help": "Decrypt text or file",
        "cli_p_help": "Password (visible in process list; prefer interactive input or --password-file)",
        "cli_p_warn": "Warning: password passed via -p is visible in the process list; prefer --password-file or interactive input",
        "cli_password_file_help": "Read password from file (avoid process list exposure)",
        "cli_f_help": "File mode",
        "cli_o_help": "Output file path",
        "cli_hash_help": "Hash file, e.g. sha256",
        "cli_lang_help": "Language",
        "analyze_input": "Enter text to analyze: ",
        "analyze_title": "Analysis result:",
        "analyze_encoding": "Encoding: {enc}",
        "analyze_type_plain": "Type: Plain text",
        "analyze_type_b64": "Type: Base64-encoded text",
        "analyze_type_aes_gcm": "Type: AES-GCM encrypted (CryptPouch format)",
        "analyze_type_aes_cbc": "Type: AES-CBC encrypted (CryptPouch format)",
        "analyze_type_binary": "Type: Unrecognized binary or encrypted data",
        "analyze_type_aes_legacy": "Type: Suspected AES ciphertext (legacy format, no version marker)",
        "analyze_try_decrypt": "Try to decrypt? (y/n): ",
        "analyze_type_chacha20": "Type: ChaCha20-Poly1305 encrypted (CryptPouch format)",
        "auto_chacha_ok": "ChaCha20-Poly1305 decrypted",
        "err_cipher_mode": "Unsupported cipher mode (gcm/cbc/chacha20)",
        "cli_cipher_help": "Cipher: gcm/cbc/chacha20 (default gcm)",
        "reencrypt_old_pwd": "Enter old password: ",
        "reencrypt_new_pwd": "Enter new password: ",
        "reencrypt_mode_prompt": "Target format (gcm/cbc/chacha20, Enter for gcm): ",
        "reencrypt_done": "Re-encryption complete",
        "reencrypt_output": "Saved to {path}",
        "batch_path_prompt": "Enter directory or file path: ",
        "batch_pattern_prompt": "File type filter (comma separated, e.g. *.txt,*.md, Enter for all): ",
        "batch_encrypted_n": "Encrypted {n} file(s)",
        "batch_decrypted_n": "Decrypted {n} file(s)",
        "batch_overwrite_hint": "Batch decryption will overwrite files with the same name.",
    }
}


class I18n:
    def __init__(self, lang: str = "zh"):
        self.lang = lang if lang in LANG else "zh"

    def t(self, key: str, **kwargs) -> str:
        template = LANG[self.lang].get(key, key)
        if kwargs:
            try:
                return template.format(**kwargs)
            except (KeyError, IndexError, ValueError):
                return template
        return template


# ====================== Output helpers: keeps decorative glyphs ======================

# ANSI color output (zero dependencies; configured via the 'color' config key).
_ANSI = {"yellow": "\x1b[33m", "red": "\x1b[31m", "reset": "\x1b[0m"}
_VT_INITIALIZED = False


def _ensure_vt() -> None:
    """On Windows, run one no-op console command so the CRT enables VT processing."""
    global _VT_INITIALIZED
    if not _VT_INITIALIZED and os.name == "nt":
        try:
            os.system("")
        except Exception:
            pass
        _VT_INITIALIZED = True


def _color_enabled() -> bool:
    """color=on -> always color; color=off -> never; color=auto -> only for a real terminal."""
    mode = CONFIG.get("color", "auto")
    if mode == "on":
        return True
    if mode == "off":
        return False
    _ensure_vt()
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


class Printer:
    def __init__(self, i18n: I18n):
        self.i18n = i18n

    @staticmethod
    def _paint(msg: str, ansi: str) -> str:
        """Wrap msg in an ANSI color when color output is active, else return it unchanged."""
        if _color_enabled():
            return f"{ansi}{msg}{_ANSI['reset']}"
        return msg

    def info(self, msg: str):
        print(f"[提示] {msg}" if self.i18n.lang == "zh" else f"[Info] {msg}")

    def ok(self, msg: str):
        print(f"[成功] {msg} " if self.i18n.lang == "zh" else f"[OK] {msg} ")

    def warn(self, msg: str):
        line = (f"[警告] {msg} (｡•́︿•̀｡)" if self.i18n.lang == "zh"
                else f"[Warning] {msg} (｡•́︿•̀｡)")
        print(self._paint(line, _ANSI["yellow"]))

    def fail(self, msg: str):
        line = (f"[错误] {msg} (╥﹏╥)" if self.i18n.lang == "zh"
                else f"[Error] {msg} (╥﹏╥)")
        print(self._paint(line, _ANSI["red"]))


# ====================== Global objects ======================

i18n = I18n()
printer = Printer(i18n)


# ====================== Dependency check and auto-install ======================

# key: pip package name; value: module name actually imported by Python
CORE_PACKAGES = {
    "pycryptodome": "Crypto",
    "argon2-cffi": "argon2",  # Argon2id key derivation for the v3 format
}
OPTIONAL_PACKAGES = {
    "pyperclip": "pyperclip",
    "qrcode": "qrcode",
    "pillow": "PIL",
    "pyzbar": "pyzbar",
}


def check_dependencies():
    missing_core = []
    missing_optional = []

    for pkg_name, import_name in CORE_PACKAGES.items():
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing_core.append(pkg_name)

    for pkg_name, import_name in OPTIONAL_PACKAGES.items():
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing_optional.append(pkg_name)

    return missing_core, missing_optional


def install_packages(packages: List[str], i18n: I18n) -> bool:
    printer = Printer(i18n)

    global_cmd = "pip install " + " ".join(packages)
    cn_cmd = "pip install " + " ".join(packages) + " -i https://pypi.tuna.tsinghua.edu.cn/simple"

    printer.info(i18n.t("install_cmd_global") + " " + global_cmd)
    printer.info(i18n.t("install_cmd_cn") + " " + cn_cmd)
    print()

    confirm = _safe_input(i18n.t("ask_install")).strip().lower()
    if confirm != "y":
        printer.warn(i18n.t("install_cancel"))
        return False

    printer.info(i18n.t("installing"))
    print()

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install"] + packages,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            printer.ok(i18n.t("install_success"))
            time.sleep(1.5)
            # Restart as a subprocess instead of os.execv so cleanup logic is not bypassed
            subprocess.Popen([sys.executable] + sys.argv)
            sys.exit(0)
            return True
        else:
            printer.fail(i18n.t("install_fail"))
            print(result.stderr)
            return False
    except Exception as e:
        printer.fail(i18n.t("install_fail"))
        print(str(e))
        return False


# ====================== Constants ======================

# ====================== User configuration (config.json + CRYPTOUCH_* env) ======================
# Priority: CLI argument > environment variable > config.json > built-in default.

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".cryptpouch")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")

DEFAULT_CONFIG = {
    "iterations": 600_000,        # PBKDF2 iterations (legacy v2 text formats)
    "rsa_bits": 2048,             # default RSA key size (2048 / 3072 / 4096)
    "lang": None,                 # default UI language: "zh" / "en" / None (ask interactively)
    "argon2_time_cost": 3,        # Argon2id time cost
    "argon2_memory_kib": 65536,   # Argon2id memory cost (64 MiB)
    "argon2_parallelism": 4,      # Argon2id parallelism
    "qr_max_len": 5000,           # QR content length limit
    "password_max_len": 128,      # password length limit
    "score_strong": 5,            # password strength thresholds
    "score_medium": 3,
    "weak_password_file": "",     # optional external weak-password dictionary path (empty = disabled)
    "check_keyboard_patterns": True,   # sliding-window QWERTY adjacency detection
    "keyboard_pattern_min_len": 4,     # minimum run length for a keyboard-pattern hit
    "check_year_patterns": True,       # word+year structure detection
    "color": "auto",                   # ANSI color output: auto (real terminal) / on / off
}

# Environment variable overrides for scripting/automation (CRYPTOUCH_*)
_CONFIG_ENV_MAP = {
    "iterations":         ("CRYPTPOUCH_ITERATIONS", "int"),
    "rsa_bits":           ("CRYPTPOUCH_RSA_BITS", "int"),
    "lang":               ("CRYPTPOUCH_LANG", "str"),
    "argon2_time_cost":   ("CRYPTPOUCH_ARGON2_TIME", "int"),
    "argon2_memory_kib":  ("CRYPTPOUCH_ARGON2_MEM", "int"),
    "argon2_parallelism": ("CRYPTPOUCH_ARGON2_PARALLEL", "int"),
    "qr_max_len":         ("CRYPTPOUCH_QR_MAX_LEN", "int"),
    "password_max_len":   ("CRYPTPOUCH_PASSWORD_MAX", "int"),
    "score_strong":       ("CRYPTPOUCH_SCORE_STRONG", "int"),
    "score_medium":       ("CRYPTPOUCH_SCORE_MEDIUM", "int"),
    "weak_password_file": ("CRYPTPOUCH_WEAK_PASSWORD_FILE", "str"),
    "check_keyboard_patterns": ("CRYPTPOUCH_CHECK_KEYBOARD_PATTERNS", "bool"),
    "keyboard_pattern_min_len": ("CRYPTPOUCH_KEYBOARD_PATTERN_MIN_LEN", "int"),
    "check_year_patterns": ("CRYPTPOUCH_CHECK_YEAR_PATTERNS", "bool"),
    "color":              ("CRYPTPOUCH_COLOR", "str"),
}


def _config_env_value(name: str):
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    return raw.strip()


def load_config(config_path: Optional[str] = None) -> dict:
    """Load the user config file, merge with built-in defaults, then apply CRYPTOUCH_* env overrides.

    A missing or unreadable config file is not an error: defaults are used silently
    (the tool must keep working on fresh machines and in library imports)."""
    cfg = dict(DEFAULT_CONFIG)
    path = config_path or CONFIG_PATH
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict):
            for key in cfg:
                if key in raw and raw[key] is not None:
                    cfg[key] = raw[key]
    except (OSError, ValueError):
        pass  # missing / corrupt config: fall back to defaults

    for key, (env_name, kind) in _CONFIG_ENV_MAP.items():
        raw = _config_env_value(env_name)
        if raw is None:
            continue
        try:
            if kind == "int":
                cfg[key] = int(raw)
            elif kind == "bool":
                cfg[key] = raw.strip().lower() in ("1", "true", "yes", "on")
            else:
                cfg[key] = raw
        except ValueError:
            continue  # malformed env value: ignore, keep current value

    # Sanity clamps (never let a bad config cripple the tool)
    try:
        cfg["iterations"] = max(1_000, int(cfg["iterations"]))
    except (TypeError, ValueError):
        cfg["iterations"] = DEFAULT_CONFIG["iterations"]
    if cfg["rsa_bits"] not in (2048, 3072, 4096):
        cfg["rsa_bits"] = DEFAULT_CONFIG["rsa_bits"]
    if cfg["lang"] not in ("zh", "en"):
        cfg["lang"] = None
    if cfg["color"] not in ("auto", "on", "off"):
        cfg["color"] = DEFAULT_CONFIG["color"]
    for key in ("argon2_time_cost", "argon2_parallelism", "qr_max_len",
                "password_max_len", "score_strong", "score_medium",
                "keyboard_pattern_min_len"):
        try:
            cfg[key] = max(1, int(cfg[key]))
        except (TypeError, ValueError):
            cfg[key] = DEFAULT_CONFIG[key]
    try:
        cfg["argon2_memory_kib"] = max(8 * 1024, int(cfg["argon2_memory_kib"]))
    except (TypeError, ValueError):
        cfg["argon2_memory_kib"] = DEFAULT_CONFIG["argon2_memory_kib"]
    return cfg


# Loaded once at import time; applies to interactive, CLI and library entry points alike.
CONFIG = load_config()


def _validate_config_values(updates: dict) -> dict:
    """Type/range-check a set of config updates; unknown keys are rejected."""
    out = {}
    for key, value in updates.items():
        if key not in DEFAULT_CONFIG:
            raise ValueError(i18n.t("cfg_unknown_key", k=key))
        if value is None:
            out[key] = None
            continue
        if key == "lang":
            if value not in ("zh", "en"):
                raise ValueError(i18n.t("cfg_invalid_value", k=key, v=value))
        elif key in ("check_keyboard_patterns", "check_year_patterns"):
            if not isinstance(value, bool):
                raise ValueError(i18n.t("cfg_invalid_value", k=key, v=value))
        elif key == "rsa_bits":
            if value not in (2048, 3072, 4096):
                raise ValueError(i18n.t("cfg_invalid_value", k=key, v=value))
        elif key == "weak_password_file":
            if not isinstance(value, str):
                raise ValueError(i18n.t("cfg_invalid_value", k=key, v=value))
        elif key == "color":
            if value not in ("auto", "on", "off"):
                raise ValueError(i18n.t("cfg_invalid_value", k=key, v=value))
        else:
            # numeric keys: iterations, argon2_*, qr_max_len, password_max_len,
            # score_*, keyboard_pattern_min_len
            try:
                ivalue = int(value)
            except (TypeError, ValueError):
                raise ValueError(i18n.t("cfg_invalid_value", k=key, v=value))
            minimum = 8 * 1024 if key == "argon2_memory_kib" else (1_000 if key == "iterations" else 1)
            if ivalue < minimum:
                raise ValueError(i18n.t("cfg_invalid_value", k=key, v=value))
            out[key] = ivalue
            continue
        out[key] = value
    return out


def _refresh_derived_constants() -> None:
    """Re-bind module constants derived from CONFIG (used by set_config(reload=True))."""
    global DEFAULT_ITERATIONS, RSA_KEY_BITS, PASSWORD_MAX_LEN, SCORE_STRONG
    global SCORE_MEDIUM, QR_MAX_LEN, ARGON2_TIME_COST, ARGON2_MEMORY_COST_KIB
    global ARGON2_PARALLELISM, KEYBOARD_PATTERN_MIN_LEN
    DEFAULT_ITERATIONS = CONFIG["iterations"]
    RSA_KEY_BITS = CONFIG["rsa_bits"]
    PASSWORD_MAX_LEN = CONFIG["password_max_len"]
    SCORE_STRONG = CONFIG["score_strong"]
    SCORE_MEDIUM = CONFIG["score_medium"]
    QR_MAX_LEN = CONFIG["qr_max_len"]
    ARGON2_TIME_COST = CONFIG["argon2_time_cost"]
    ARGON2_MEMORY_COST_KIB = CONFIG["argon2_memory_kib"]
    ARGON2_PARALLELISM = CONFIG["argon2_parallelism"]
    KEYBOARD_PATTERN_MIN_LEN = CONFIG["keyboard_pattern_min_len"]


def set_config(config_path: Optional[str] = None, reload: bool = False, **kwargs) -> dict:
    """Persist config updates to ~/.cryptpouch/config.json with an atomic write.

    Merge semantics: read the existing JSON, deep-merge the new values, validate, write back.
    Only the JSON layer is written: CLI > env > config.json > defaults priority is preserved,
    so an environment variable still overrides the file at load time.

    Changes take effect for the next process (derived constants are bound at import time);
    pass reload=True to refresh the in-process CONFIG and derived constants immediately."""
    path = config_path or CONFIG_PATH
    existing = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            existing = json.load(f)
        if not isinstance(existing, dict):
            existing = {}
    except (OSError, ValueError):
        existing = {}
    merged = dict(existing)
    validated = _validate_config_values(kwargs)
    for key, value in validated.items():
        if value is None:
            merged.pop(key, None)
        else:
            merged[key] = value
    dir_name = os.path.dirname(path) or "."
    os.makedirs(dir_name, exist_ok=True)
    tmp_path = os.path.join(dir_name, ".config.json.tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp_path, path)
    if reload:
        global CONFIG
        CONFIG = load_config(path)
        _refresh_derived_constants()
    return dict(CONFIG) if reload else dict(merged)

# Directory of this script: generated keys, QR images, etc. are written here by default
# (avoids Permission denied under store Python where the working directory is read-only)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_ITERATIONS = CONFIG["iterations"]
# The legacy standalone tool (text-encryptor.py) uses 100000 iterations with no format prefix;
# decryption of prefixless legacy ciphertext falls back to that iteration count
LEGACY_ITERATIONS = 100_000

# Compatibility probe matrix for prefixless legacy ciphertext: (PBKDF2 iterations, HMAC hash, key bytes)
# Ordered by hit probability; covers CryptPouch legacy, the old tool, and common simple tools (SHA1/low iterations/AES-128)
LEGACY_DECRYPT_PROBES = [
    (DEFAULT_ITERATIONS, "SHA256", 32),  # CryptPouch legacy format
    (LEGACY_ITERATIONS, "SHA256", 32),   # text-encryptor.py (the old tool)
    (100_000, "SHA1", 32),               # common tools (PBKDF2 default HMAC-SHA1)
    (10_000, "SHA256", 32),
    (100_000, "MD5", 32),
    (1_000, "SHA256", 32),               # default in simple tools / tutorial examples
    (10_000, "SHA1", 32),
    (1_000, "SHA1", 32),
    (100_000, "SHA256", 16),             # AES-128 variant
]
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 32
# RSA key size (2048 bits is the current recommended minimum)
RSA_KEY_BITS = CONFIG["rsa_bits"]
# Password length limit: prevents extremely long passwords from slowing Argon2/PBKDF2 (DoS surface)
PASSWORD_MAX_LEN = CONFIG["password_max_len"]
# Password strength score thresholds (tunable via config.json)
SCORE_STRONG = CONFIG["score_strong"]
SCORE_MEDIUM = CONFIG["score_medium"]
# QR content length limit (tunable via config.json)
QR_MAX_LEN = CONFIG["qr_max_len"]
KEYBOARD_PATTERN_MIN_LEN = CONFIG["keyboard_pattern_min_len"]

PREFIX_AES_GCM_V2 = b"$AG2$"
PREFIX_AES_CBC_V2 = b"$AC2$"
# v3: Argon2id key derivation + AES-256-GCM (formal versioned format)
PREFIX_AES_V3 = b"$CP3$"
# v2.8: ChaCha20-Poly1305 AEAD (Argon2id-derived key, RFC 8439) - 12-byte nonce + 16-byte tag
PREFIX_CHACHA20 = b"$CC1$"

# Argon2id parameters (OWASP recommended profile: 3 passes / 64 MiB / 4 parallelism; tunable via config.json)
ARGON2_TIME_COST = CONFIG["argon2_time_cost"]
ARGON2_MEMORY_COST_KIB = CONFIG["argon2_memory_kib"]   # 64 MiB
ARGON2_PARALLELISM = CONFIG["argon2_parallelism"]
ARGON2_SALT_SIZE = 16
ARGON2_HASH_LEN = 32             # AES-256


# ====================== Custom exceptions ======================

class CryptoToolError(Exception):
    pass


class CipherCorruptedError(CryptoToolError):
    pass


class PasswordError(CryptoToolError):
    pass


class FormatNotSupportedError(CryptoToolError):
    pass


# ====================== Utility functions ======================

def _wipe_memory(buf) -> None:
    """Zero a mutable buffer (bytearray) in place.

    Used after derived keys are no longer needed. Python bytes/str objects are
    immutable and cannot be erased; wrapping them in a bytearray at the point of
    use and zeroing it here is the practical memory-hygiene step available."""
    if isinstance(buf, bytearray):
        buf[:] = b"\x00" * len(buf)


def normalize_path(path_str: str) -> str:
    """Normalize a user-provided path: strip drag-drop quotes/spaces and resolve ../ and . sequences.

    Note: this is a local single-user tool; the user supplies the target paths, and the attacker is the
    user, so no directory whitelist is enforced (it would prevent encrypting files in arbitrary locations).
    This function only rejects illegal characters such as NUL and resolves redundant . and .. so later
    file operations receive a clean, normalized path."""
    cleaned = path_str.strip().strip('"').strip("'")
    if "\x00" in cleaned:
        raise ValueError(i18n.t("err_bad_path"))
    return os.path.normpath(cleaned)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("PKCS7 padding error")
    padding_len = data[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("PKCS7 padding error")
    # Verify every padding byte equals the padding length (guards against Padding Oracle style errors)
    if not hmac.compare_digest(data[-padding_len:], bytes([padding_len] * padding_len)):
        raise ValueError("PKCS7 padding error")
    return data[:-padding_len]


def _get_hash_module(name: str):
    """Return the Crypto.Hash module by name; unknown names raise (no silent fallback)."""
    from Crypto.Hash import SHA256, SHA1, MD5
    modules = {"SHA256": SHA256, "SHA1": SHA1, "MD5": MD5}
    if name not in modules:
        raise ValueError(i18n.t("err_hash_alg"))
    return modules[name]


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS,
               hash_module=None, dk_len: int = 32) -> bytes:
    """PBKDF2 key derivation. hash_module defaults to SHA256; dk_len selects AES-128/256."""
    from Crypto.Protocol.KDF import PBKDF2
    if hash_module is None:
        hash_module = _get_hash_module("SHA256")
    return PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=dk_len,
        count=iterations,
        hmac_hash_module=hash_module
    )


def derive_argon2_key(password: str, salt: bytes) -> bytes:
    """Argon2id key derivation (memory-hard, resistant to GPU/ASIC parallel cracking)."""
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID
    )


def _cbc_derive_key_pair(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS):
    """Derive the CBC encryption key pair: the master key is split by HKDF into an
    encryption key and a MAC key (key separation, Encrypt-then-MAC)."""
    from Crypto.Protocol.KDF import HKDF

    master = derive_key(password, salt, iterations)
    h = _get_hash_module("SHA256")
    enc_key = HKDF(master, 32, salt, h, context=b"CryptPouch-enc")
    mac_key = HKDF(master, 32, salt, h, context=b"CryptPouch-mac")
    return enc_key, mac_key


def _note_legacy_params(iterations: int, hash_name: str, dk_len: int):
    """When legacy decryption matches non-default parameters, inform the user of the parameters used."""
    if iterations != DEFAULT_ITERATIONS or hash_name != "SHA256" or dk_len != 32:
        printer.info(i18n.t("legacy_decrypt_hint", iters=iterations, hash=hash_name))


def _is_readable_text(raw: bytes) -> bool:
    """Roughly judge whether bytes are readable text (false-positive filter for CBC unauthenticated probing).
    A minimum length gate is applied: very short plaintext (1-3 bytes) cannot be reliably distinguished
    and is treated as unreadable, preventing binary data from being accepted due to a low threshold."""
    if len(raw) < 4:
        return False
    text, enc = detect_decode(raw)
    return _encoding_score(text, enc) >= max(1, len(text) * 0.5)


# ====================== AES-GCM Encrypt/Decrypt ======================

class AESGCMTool:
    def __init__(self, password: str, iterations: int = DEFAULT_ITERATIONS):
        _validate_password_len(password)
        self.password = password
        self.iterations = iterations

    def encrypt(self, plain_text: str) -> str:
        """v3 format: Argon2id derivation + AES-256-GCM, prefixed with $CP3$."""
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes

        salt = get_random_bytes(ARGON2_SALT_SIZE)
        nonce = get_random_bytes(NONCE_SIZE)
        key = bytearray(derive_argon2_key(self.password, salt))
        try:
            cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode("utf-8"))
        finally:
            _wipe_memory(key)

        pack = PREFIX_AES_V3 + salt + nonce + tag + ciphertext
        return base64.b64encode(pack).decode("utf-8")

    def decrypt(self, b64_str: str) -> str:
        from Crypto.Cipher import AES

        try:
            pack = _decode_pack_b64(b64_str)
        except base64.binascii.Error:
            raise CipherCorruptedError(i18n.t("err_b64_corrupted"))

        # v3: Argon2id + $CP3$ prefix (formal format)
        if pack.startswith(PREFIX_AES_V3):
            data = pack[len(PREFIX_AES_V3):]
            if len(data) < ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE:
                raise CipherCorruptedError(i18n.t("err_len_invalid"))
            salt = data[:ARGON2_SALT_SIZE]
            nonce = data[ARGON2_SALT_SIZE:ARGON2_SALT_SIZE + NONCE_SIZE]
            tag = data[ARGON2_SALT_SIZE + NONCE_SIZE:ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE]
            ciphertext = data[ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE:]

            key = bytearray(derive_argon2_key(self.password, salt))
            try:
                cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
                try:
                    raw = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError:
                    raise PasswordError(i18n.t("err_pwd_or_tamper"))
            finally:
                _wipe_memory(key)
            return _decode_with_hint(raw)

        # v2: PBKDF2 600k + $AG2$ prefix (fast path)
        is_v2 = pack.startswith(PREFIX_AES_GCM_V2)
        offset = len(PREFIX_AES_GCM_V2) if is_v2 else 0
        data = pack[offset:]

        min_len = SALT_SIZE + NONCE_SIZE + TAG_SIZE
        if len(data) < min_len:
            raise CipherCorruptedError(i18n.t("err_len_invalid"))

        salt = data[:SALT_SIZE]
        nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        tag = data[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + TAG_SIZE]
        ciphertext = data[SALT_SIZE + NONCE_SIZE + TAG_SIZE:]

        if is_v2:
            # With version prefix: use the current iteration count (fast path)
            key = bytearray(derive_key(self.password, salt, self.iterations))
            try:
                cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
                try:
                    raw = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError:
                    raise PasswordError(i18n.t("err_pwd_or_tamper"))
            finally:
                _wipe_memory(key)
            return _decode_with_hint(raw)

        # Prefixless legacy: iterate the compatibility probe matrix (iterations x hash x key length)
        for iterations, hash_name, dk_len in LEGACY_DECRYPT_PROBES:
            key = bytearray(derive_key(self.password, salt, iterations, _get_hash_module(hash_name), dk_len))
            try:
                cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
                try:
                    raw = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError:
                    continue
            finally:
                _wipe_memory(key)
            _note_legacy_params(iterations, hash_name, dk_len)
            return _decode_with_hint(raw)

        raise PasswordError(i18n.t("err_pwd_or_tamper"))


# ====================== AES-CBC + HMAC Encrypt/Decrypt ======================

class AESCBCWithHMACTool:
    def __init__(self, password: str, iterations: int = DEFAULT_ITERATIONS):
        _validate_password_len(password)
        self.password = password
        self.iterations = iterations

    def encrypt(self, plain_text: str) -> str:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        from Crypto.Hash import HMAC, SHA256

        salt = get_random_bytes(SALT_SIZE)
        iv = get_random_bytes(IV_SIZE)
        enc_key, mac_key = _cbc_derive_key_pair(self.password, salt, self.iterations)
        enc_key = bytearray(enc_key)
        mac_key = bytearray(mac_key)
        try:
            cipher = AES.new(bytes(enc_key), AES.MODE_CBC, iv=iv)
            padded = pkcs7_pad(plain_text.encode("utf-8"))
            ciphertext = cipher.encrypt(padded)

            h = HMAC.new(bytes(mac_key), digestmod=SHA256)
            h.update(iv + ciphertext)
            mac = h.digest()
        finally:
            _wipe_memory(enc_key)
            _wipe_memory(mac_key)

        pack = PREFIX_AES_CBC_V2 + salt + iv + mac + ciphertext
        return base64.b64encode(pack).decode("utf-8")

    def decrypt(self, b64_str: str) -> str:
        from Crypto.Cipher import AES
        from Crypto.Hash import HMAC, SHA256

        try:
            pack = _decode_pack_b64(b64_str)
        except base64.binascii.Error:
            raise CipherCorruptedError(i18n.t("err_b64_corrupted"))

        is_v2 = pack.startswith(PREFIX_AES_CBC_V2)
        offset = len(PREFIX_AES_CBC_V2) if is_v2 else 0
        data = pack[offset:]

        if is_v2:
            min_len = SALT_SIZE + IV_SIZE + HMAC_SIZE + 16
            if len(data) < min_len:
                raise CipherCorruptedError(i18n.t("err_len_invalid"))

            salt = data[:SALT_SIZE]
            iv = data[SALT_SIZE:SALT_SIZE + IV_SIZE]
            mac = data[SALT_SIZE + IV_SIZE:SALT_SIZE + IV_SIZE + HMAC_SIZE]
            ciphertext = data[SALT_SIZE + IV_SIZE + HMAC_SIZE:]

            # First verify with the separated-key scheme (new format);
            # fall back to the same-key scheme on failure (legacy $AC2$ compatibility, warns to re-encrypt)
            verified = False
            schemes = (
                _cbc_derive_key_pair(self.password, salt, self.iterations),
                (derive_key(self.password, salt, self.iterations),
                 derive_key(self.password, salt, self.iterations)),
            )
            for idx, (enc_key, mac_key) in enumerate(schemes):
                enc_key = bytearray(enc_key)
                mac_key = bytearray(mac_key)
                try:
                    h = HMAC.new(bytes(mac_key), digestmod=SHA256)
                    h.update(iv + ciphertext)
                    try:
                        h.verify(mac)
                    except ValueError:
                        continue
                    cipher = AES.new(bytes(enc_key), AES.MODE_CBC, iv=iv)
                    try:
                        raw_padded = cipher.decrypt(ciphertext)
                        raw = pkcs7_unpad(raw_padded)
                    except ValueError:
                        raise PasswordError(i18n.t("err_pwd_or_tamper"))
                finally:
                    _wipe_memory(enc_key)
                    _wipe_memory(mac_key)
                verified = True
                if idx == 1:
                    # Legacy same-key scheme matched: remind the user to re-encrypt
                    printer.warn(i18n.t("ac2_legacy_hint"))
                return _decode_with_hint(raw)
            if not verified:
                raise PasswordError(i18n.t("err_pwd_or_tamper"))
        else:
            if len(data) < SALT_SIZE + IV_SIZE + 16:
                raise CipherCorruptedError(i18n.t("err_len_invalid"))

            salt = data[:SALT_SIZE]
            iv = data[SALT_SIZE:SALT_SIZE + IV_SIZE]
            ciphertext = data[SALT_SIZE + IV_SIZE:]
            # Prefixless legacy (no HMAC): iterate the compatibility probe matrix
            for iterations, hash_name, dk_len in LEGACY_DECRYPT_PROBES:
                key = bytearray(derive_key(self.password, salt, iterations, _get_hash_module(hash_name), dk_len))
                try:
                    cipher = AES.new(bytes(key), AES.MODE_CBC, iv=iv)
                    try:
                        raw_padded = cipher.decrypt(ciphertext)
                        raw = pkcs7_unpad(raw_padded)
                    except ValueError:
                        continue
                finally:
                    _wipe_memory(key)
                # CBC without authentication: a wrong candidate may produce valid padding by chance,
                # use readability to filter false positives and continue probing on garbage
                if not _is_readable_text(raw):
                    continue
                _note_legacy_params(iterations, hash_name, dk_len)
                return _decode_with_hint(raw)
            raise PasswordError(i18n.t("err_pwd_or_tamper"))


# ====================== ChaCha20-Poly1305 Encrypt/Decrypt ======================

class ChaCha20Poly1305Tool:
    """ChaCha20-Poly1305 AEAD (RFC 8439) with Argon2id key derivation ($CC1$ format).

    Modern authenticated encryption; it is notably faster than AES-GCM on devices
    without AES hardware acceleration (ARM, Raspberry Pi, ...)."""

    def __init__(self, password: str, iterations: int = DEFAULT_ITERATIONS):
        _validate_password_len(password)
        self.password = password
        self.iterations = iterations

    def encrypt(self, plain_text: str) -> str:
        from Crypto.Cipher import ChaCha20_Poly1305
        from Crypto.Random import get_random_bytes

        salt = get_random_bytes(ARGON2_SALT_SIZE)
        nonce = get_random_bytes(NONCE_SIZE)  # 12-byte nonce (RFC 8439)
        key = bytearray(derive_argon2_key(self.password, salt))
        try:
            cipher = ChaCha20_Poly1305.new(key=bytes(key), nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode("utf-8"))
        finally:
            _wipe_memory(key)

        pack = PREFIX_CHACHA20 + salt + nonce + tag + ciphertext
        return base64.b64encode(pack).decode("utf-8")

    def decrypt(self, b64_str: str) -> str:
        from Crypto.Cipher import ChaCha20_Poly1305

        try:
            pack = _decode_pack_b64(b64_str)
        except base64.binascii.Error:
            raise CipherCorruptedError(i18n.t("err_b64_corrupted"))

        if not pack.startswith(PREFIX_CHACHA20):
            # Not our format: report as wrong password / not ciphertext so the
            # caller can route to another cipher family without legacy probing
            raise PasswordError(i18n.t("err_pwd_or_tamper"))

        data = pack[len(PREFIX_CHACHA20):]
        if len(data) < ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE:
            raise CipherCorruptedError(i18n.t("err_len_invalid"))
        salt = data[:ARGON2_SALT_SIZE]
        nonce = data[ARGON2_SALT_SIZE:ARGON2_SALT_SIZE + NONCE_SIZE]
        tag = data[ARGON2_SALT_SIZE + NONCE_SIZE:ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE]
        ciphertext = data[ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE:]

        key = bytearray(derive_argon2_key(self.password, salt))
        try:
            cipher = ChaCha20_Poly1305.new(key=bytes(key), nonce=nonce)
            raw = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise PasswordError(i18n.t("err_pwd_or_tamper"))
        finally:
            _wipe_memory(key)
        return _decode_with_hint(raw)


# ====================== Password generation and strength check ======================

def generate_random_password(length: int = 16, include_special: bool = True) -> str:
    if length < 8:
        raise ValueError("Password length at least 8")

    base_chars = string.ascii_letters + string.digits
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    chars = base_chars + special_chars if include_special else base_chars

    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    if include_special:
        password.append(secrets.choice(special_chars))

    password += [secrets.choice(chars) for _ in range(length - len(password))]
    return ''.join(secrets.SystemRandom().sample(password, len(password)))


# Weak-password dictionary support (optional): path validation, size cap, graceful skip.
WEAK_PASSWORD_MAX_BYTES = 32 * 1024 * 1024
_WEAK_DICT_CACHE = {"path": None, "words": None}


def _load_weak_password_dict(path: Optional[str] = None) -> set:
    """Load the external weak-password dictionary once (cached).

    Missing, oversized or unreadable dictionaries degrade gracefully to 'check skipped'
    with a warning - an optional feature must never break the main flow."""
    path = (path or "").strip() or (CONFIG.get("weak_password_file") or "").strip()
    if not path:
        return set()
    if _WEAK_DICT_CACHE["path"] == path and _WEAK_DICT_CACHE["words"] is not None:
        return _WEAK_DICT_CACHE["words"]
    words = set()
    try:
        if "\x00" in path:
            raise ValueError(i18n.t("err_bad_path"))
        dict_path = os.path.normpath(os.path.expanduser(path))
        if not os.path.isfile(dict_path):
            raise OSError(i18n.t("dict_missing", path=dict_path))
        if os.path.getsize(dict_path) > WEAK_PASSWORD_MAX_BYTES:
            raise OSError(i18n.t("dict_too_large", limit=WEAK_PASSWORD_MAX_BYTES))
        with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip().lower()
                if w:
                    words.add(w)
                    if len(words) >= 1_000_000:
                        break  # hard safety cap on the in-memory set
    except (OSError, ValueError) as e:
        printer.warn(i18n.t("dict_skip", reason=str(e)[:100]))
        words = set()
    _WEAK_DICT_CACHE["path"] = path
    _WEAK_DICT_CACHE["words"] = words
    return words


# QWERTY layout as (row, col); the home row is offset 0.5 so columns/diagonals resolve cleanly.
_KEYBOARD_LAYOUT = {
    "1": (0, 0.0), "2": (0, 1.0), "3": (0, 2.0), "4": (0, 3.0), "5": (0, 4.0),
    "6": (0, 5.0), "7": (0, 6.0), "8": (0, 7.0), "9": (0, 8.0), "0": (0, 9.0),
    "q": (1, 0.0), "w": (1, 1.0), "e": (1, 2.0), "r": (1, 3.0), "t": (1, 4.0),
    "y": (1, 5.0), "u": (1, 6.0), "i": (1, 7.0), "o": (1, 8.0), "p": (1, 9.0),
    "a": (2, 0.5), "s": (2, 1.5), "d": (2, 2.5), "f": (2, 3.5), "g": (2, 4.5),
    "h": (2, 5.5), "j": (2, 6.5), "k": (2, 7.5), "l": (2, 8.5),
    "z": (3, 1.0), "x": (3, 2.0), "c": (3, 3.0), "v": (3, 4.0), "b": (3, 5.0),
    "n": (3, 6.0), "m": (3, 7.0),
}


def _keyboard_run_len(pwd: str) -> int:
    """Longest run of adjacent QWERTY keys (rows, columns and diagonals), both directions."""
    low = pwd.lower()
    best = run = 1
    for i in range(1, len(low)):
        prev = _KEYBOARD_LAYOUT.get(low[i - 1])
        cur = _KEYBOARD_LAYOUT.get(low[i])
        if prev is None or cur is None:
            run = 1
            continue
        dr = cur[0] - prev[0]
        dc = cur[1] - prev[1]
        if (dr == 0 and abs(dc) == 1.0) or (abs(dr) == 1 and abs(dc) <= 1.5):
            run += 1
        else:
            run = 1
        if run > best:
            best = run
    return best


def check_password_strength(pwd: str) -> Tuple[str, List[str]]:
    score = 0
    tips = []

    if len(pwd) >= 16:
        score += 3
    elif len(pwd) >= 12:
        score += 2
    elif len(pwd) >= 8:
        score += 1
    else:
        tips.append(i18n.t("tip_len_short"))

    has_lower = any(c.islower() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_special = any(not c.isalnum() for c in pwd)
    char_types = sum([has_lower, has_upper, has_digit, has_special])
    score += char_types

    if char_types < 3:
        tips.append(i18n.t("tip_char_types"))

    weak_list = {
        "123456", "password", "12345678", "qwerty", "abc123", "123456789",
        "1234567890", "admin", "letmein", "welcome", "monkey", "dragon",
        "111111", "000000", "123123", "1234567", "qwerty123", "password1",
        "iloveyou", "sunshine", "princess", "football", "baseball", "shadow",
        "master", "passw0rd", "p@ssw0rd", "qwertyuiop", "asdfghjkl",
        "zxcvbnm", "1qaz2wsx", "qazwsx", "1q2w3e4r", "zaq12wsx",
        "woaini", "5201314", "1314520", "abc", "abcd", "1234", "12345",
        "aaaaaa", "aaaaaaa", "a123456", "123456a",
        "asdf", "zxcv", "987654321", "qq123456", "a1b2c3", "pass1234",
        "admin123", "123abc", "abc1234", "123qwe", "qwe123", "a12345",
        "test123", "user123", "login123", "love1314", "woaini1314",
    }
    low = pwd.lower()
    if low in weak_list or low in _load_weak_password_dict():
        score = 0
        tips.append(i18n.t("tip_weak_common"))

    # Keyboard walk sequences: sliding-window adjacency over the QWERTY layout
    # (rows, columns and diagonals; single detector, not a parallel fixed-string list)
    if CONFIG.get("check_keyboard_patterns", True) and _keyboard_run_len(pwd) >= KEYBOARD_PATTERN_MIN_LEN:
        score = 0
        tips.append(i18n.t("tip_keyboard"))

    # Pure digits / single repeated character / consecutive ascending or descending sequences
    seq_ok = False
    if pwd.isdigit():
        seq_ok = True
    elif len(set(pwd)) == 1:
        seq_ok = True
    elif len(pwd) >= 4:
        import re as _re
        if _re.fullmatch(r"(?:0123456789|123456789|23456789|abcdefghijklmnopqrstuvwxyz|abcdefghijk|9876543210)", low):
            seq_ok = True
    if seq_ok and score > 0:
        score = max(1, score - 2)
        tips.append(i18n.t("tip_sequence"))

    # Word+year patterns (e.g. Summer2024): only when the whole password is 'word + year',
    # so a password that merely contains a year (birthdays, anniversaries) is not penalized.
    if CONFIG.get("check_year_patterns", True) and score > 0:
        import re as _re
        if len(pwd) <= 16 and _re.fullmatch(r"[A-Za-z]{2,}(?:19[0-9]{2}|20[0-9]{2})", pwd):
            score = max(1, score - 2)
            tips.append(i18n.t("tip_year"))

    if score >= SCORE_STRONG:
        level = i18n.t("strength_strong")
    elif score >= SCORE_MEDIUM:
        level = i18n.t("strength_medium")
    else:
        level = i18n.t("strength_weak")

    return level, tips


# ====================== Automatic encoding detection ======================

# Scoring candidates: strict UTF-8 first; on failure, pick the best by readability among the rest
ENCODING_PRIORITY = ("utf-8", "gbk", "big5", "shift_jis")
# Final fallback: Latin-1 maps every byte to a character, loses nothing, never raises
FALLBACK_ENCODING = "latin-1"


def _encoding_score(text: str, enc: str) -> int:
    """Score decoded text for readability: normal characters add points, mojibake signals subtract.

    Key feature: GBK bytes misdecoded as Shift_JIS produce many half-width kana (U+FF61-U+FF9F),
    while genuine Japanese text is dominated by full-width kana (U+3040-U+30FF);
    candidates inconsistent with the target encoding are penalized accordingly.
    """
    score = 0
    full_kana = 0   # full-width hiragana/katakana
    half_kana = 0   # half-width kana
    latin_ext = 0   # Latin extended characters
    cjk = 0         # CJK ideographs
    for ch in text:
        o = ord(ch)
        if ch == "\ufffd":
            score -= 50
        elif o < 0x20 or 0x7F <= o < 0xA0:
            score -= 30
        elif 0xE000 <= o <= 0xF8FF:
            score -= 10
        elif 0x3040 <= o <= 0x30FF:
            full_kana += 1
            score += 1
        elif 0xFF60 <= o <= 0xFF9F:
            half_kana += 1
            score += 1
        elif 0x4E00 <= o <= 0x9FFF:
            cjk += 1
            score += 1
        else:
            score += 1
            if 0x0080 <= o <= 0x024F:
                latin_ext += 1

    total = len(text)
    if total == 0:
        return 0

    # Text in Chinese double-byte encodings should not contain many kana or Latin extended chars
    if enc in ("gbk", "big5"):
        if (full_kana + half_kana + latin_ext) >= total * 0.3:
            score -= total * 10
    # Shift_JIS text should be kana-dominated and not overwhelmingly half-width kana;
    # a high share of full-width kana is a strong Japanese signal (GBK misdecodes only half-width), worth bonus points
    elif enc == "shift_jis":
        if (full_kana + half_kana) < total * 0.4:
            score -= total * 5
        if half_kana > full_kana:
            score -= total * 5
        if full_kana >= total * 0.5:
            score += total * 5
    return score


def detect_decode(data: bytes) -> Tuple[str, str]:
    """Auto-detect the text encoding of byte data and decode it.

    Returns (decoded text, detected encoding name).
    1) Strict UTF-8 first - its multi-byte patterns are well designed and misdetection is rare;
    2) only when UTF-8 fails, pick the highest readability score among GBK / Big5 / Shift_JIS / Latin-1
       (loose double-byte encodings overlap, so this cannot be exact, but it avoids obvious mojibake);
    3) as a last resort, decode with lenient UTF-8 so no exception is raised.
    """
    try:
        return data.decode("utf-8"), "utf-8"
    except (UnicodeDecodeError, LookupError):
        pass

    best_text, best_enc, best_score = None, None, None
    for enc in ENCODING_PRIORITY:
        if enc == "utf-8":
            continue
        try:
            text = data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        s = _encoding_score(text, enc)
        if best_score is None or s > best_score:
            best_text, best_enc, best_score = text, enc, s
    if best_text is not None:
        return best_text, best_enc
    # Latin-1 fallback: map byte by byte, preserving information and never raising
    return data.decode(FALLBACK_ENCODING), FALLBACK_ENCODING


def _decode_with_hint(data: bytes) -> str:
    """Decode bytes to text; if the detected encoding is not UTF-8, print a hint."""
    text, enc = detect_decode(data)
    if enc != "utf-8":
        printer.info(i18n.t("auto_encoding", enc=enc))
    return text


# ====================== Encoding and hashing ======================

def b64_encode(plain_text: str) -> str:
    return base64.b64encode(plain_text.encode("utf-8")).decode("utf-8")


def b64_decode(enc_str: str) -> str:
    try:
        data = base64.b64decode(enc_str, validate=True)
    except Exception:
        # Compatible with pasted input: strip whitespace and retry strict decoding;
        # non-whitespace junk is rejected (no lenient fallback)
        import re as _re
        cleaned = _re.sub(r"\s+", "", enc_str)
        try:
            data = base64.b64decode(cleaned, validate=True)
        except base64.binascii.Error:
            raise ValueError(i18n.t("err_b64_corrupted"))
    return _decode_with_hint(data)


def _decode_pack_b64(b64_str: str) -> bytes:
    """Decode ciphertext-pack Base64: strict mode first; on failure, remove whitespace (newlines/spaces/tabs)
    and retry strict decoding - tolerates pasted newlines but rejects non-whitespace junk."""
    try:
        return base64.b64decode(b64_str, validate=True)
    except Exception:
        import re as _re
        cleaned = _re.sub(r"\s+", "", b64_str)
        return base64.b64decode(cleaned, validate=True)


# Hash algorithm whitelist (shared by calc_hash / calc_file_hash)
HASH_ALGORITHMS = ("md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b")


def calc_hash(data: bytes, algorithm: str) -> str:
    alg_map = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
        "sha3_256": hashlib.sha3_256,
        "blake2b": hashlib.blake2b,
    }
    if algorithm not in alg_map:
        raise ValueError(i18n.t("err_hash_alg"))
    return alg_map[algorithm](data).hexdigest()


def calc_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(i18n.t("err_hash_alg"))
    h = hashlib.new(algorithm)
    file_size = os.path.getsize(file_path)
    read_size = 0

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
            h.update(chunk)
            read_size += len(chunk)
            if file_size > PROGRESS_THRESHOLD:
                percent = read_size / file_size * 100
                print(f"\rProgress: {percent:.1f}%", end="", flush=True)

    if file_size > PROGRESS_THRESHOLD:
        print()

    return h.hexdigest()


# ====================== RSA tools ======================

def rsa_generate_keys(protect_passphrase: Optional[str] = None,
                      key_bits: int = RSA_KEY_BITS):
    from Crypto.PublicKey import RSA

    if protect_passphrase:
        _validate_password_len(protect_passphrase)
    key = RSA.generate(key_bits)
    # Strength self-check: ensure the generated key has the expected size
    if key.size_in_bits() != key_bits:
        raise ValueError(i18n.t("err_rsa_key_strength"))
    if protect_passphrase:
        private = key.export_key(
            passphrase=protect_passphrase,
            pkcs=8,
            protection="scryptAndAES128-CBC"
        )
    else:
        private = key.export_key()
    public = key.publickey().export_key()
    return private, public


def rsa_encrypt(public_key_path: str, text: str) -> str:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256

    with open(public_key_path, "rb") as f:
        key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    data = text.encode("utf-8")
    max_len = key.size_in_bytes() - 2 * SHA256.digest_size - 2
    if len(data) > max_len:
        raise ValueError(i18n.t("err_rsa_text_long"))
    ct = cipher.encrypt(data)
    return base64.b64encode(ct).decode()


def rsa_decrypt(private_key_path: str, b64_text: str, passphrase: Optional[str] = None) -> str:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256

    if passphrase:
        _validate_password_len(passphrase)
    with open(private_key_path, "rb") as f:
        key_data = f.read()
    key = RSA.import_key(key_data, passphrase=passphrase)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    try:
        raw = base64.b64decode(b64_text)
    except base64.binascii.Error:
        raise ValueError(i18n.t("err_b64_corrupted"))
    pt = cipher.decrypt(raw)
    return _decode_with_hint(pt)


# ====================== QR code tools ======================

def generate_qr(text: str, save_path: Optional[str] = None):
    import qrcode

    # Content length limit: excessive content may fail to encode or cause DoS
    if len(text) > QR_MAX_LEN:
        raise ValueError(i18n.t("qr_too_long"))

    qr = qrcode.QRCode(border=2)
    qr.add_data(text)
    qr.make(fit=True)

    printer.info(i18n.t("qr_preview"))
    qr.print_ascii(invert=True)

    if save_path:
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(save_path)
        printer.ok(i18n.t("qr_saved_to", path=save_path))


def decode_qr(image_path: str) -> List[str]:
    from pyzbar.pyzbar import decode
    from PIL import Image

    with Image.open(image_path) as img:
        results = decode(img)
    return [_decode_with_hint(res.data) for res in results]


# ====================== File encryption/decryption ======================

# Streaming chunk size (large files are not fully loaded into memory)
CHUNK_SIZE = 65536
# Progress indicator threshold for large files
PROGRESS_THRESHOLD = 10 * 1024 * 1024


def encrypt_file(input_path: str, output_path: str, password: str):
    """v3 streaming encryption: $CP3$ + Argon2id + AES-256-GCM, tag written at the end of the file."""
    _validate_password_len(password)
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    salt = get_random_bytes(ARGON2_SALT_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)
    key = bytearray(derive_argon2_key(password, salt))
    # The derived key is no longer needed as a standalone value once the cipher
    # object is built (the cipher keeps its own internal copy); zero it in place.
    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
    _wipe_memory(key)

    file_size = os.path.getsize(input_path)
    show_progress = file_size > PROGRESS_THRESHOLD

    with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
        f_out.write(PREFIX_AES_V3)
        f_out.write(salt)
        f_out.write(nonce)
        read_size = 0
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            f_out.write(cipher.encrypt(chunk))
            read_size += len(chunk)
            if show_progress:
                percent = read_size / file_size * 100
                print(f"\rProgress: {percent:.1f}%", end="", flush=True)
        f_out.write(cipher.digest())

    if show_progress:
        print()
    _restrict_permissions(output_path)


def decrypt_file(input_path: str, output_path: str, password: str):
    _validate_password_len(password)
    from Crypto.Cipher import AES

    file_size = os.path.getsize(input_path)

    with open(input_path, "rb") as f_in:
        header = f_in.read(len(PREFIX_AES_V3))

        if header == PREFIX_AES_V3:
            # v3 streaming: salt + nonce + ciphertext + tag (at the end)
            if file_size < len(PREFIX_AES_V3) + ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE:
                raise CipherCorruptedError(i18n.t("err_len_invalid"))
            salt = f_in.read(ARGON2_SALT_SIZE)
            nonce = f_in.read(NONCE_SIZE)
            key = bytearray(derive_argon2_key(password, salt))
            cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
            _wipe_memory(key)

            data_len = file_size - len(PREFIX_AES_V3) - ARGON2_SALT_SIZE - NONCE_SIZE - TAG_SIZE
            show_progress = file_size > PROGRESS_THRESHOLD
            try:
                with open(output_path, "wb") as f_out:
                    remaining = data_len
                    read_size = 0
                    while remaining > 0:
                        chunk = f_in.read(min(CHUNK_SIZE, remaining))
                        if not chunk:
                            break
                        f_out.write(cipher.decrypt(chunk))
                        read_size += len(chunk)
                        remaining -= len(chunk)
                        if show_progress:
                            percent = read_size / data_len * 100
                            print(f"\rProgress: {percent:.1f}%", end="", flush=True)
                    tag = f_in.read(TAG_SIZE)
                    try:
                        cipher.verify(tag)
                    except ValueError:
                        raise PasswordError(i18n.t("err_pwd_or_file_tamper"))
            except Exception:
                # Decryption failed: remove the partial output to avoid leaving a corrupted file
                if os.path.exists(output_path):
                    os.remove(output_path)
                raise
            finally:
                if show_progress:
                    print()
            _restrict_permissions(output_path)
            return

        elif header == PREFIX_AES_GCM_V2:
            # v2: salt + nonce + tag + ciphertext
            salt = f_in.read(SALT_SIZE)
            nonce = f_in.read(NONCE_SIZE)
            tag = f_in.read(TAG_SIZE)
            ciphertext = f_in.read()

            key = bytearray(derive_key(password, salt))
            cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
            _wipe_memory(key)

            try:
                plain_data = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                raise PasswordError(i18n.t("err_pwd_or_file_tamper"))

            with open(output_path, "wb") as f_out:
                f_out.write(plain_data)
            _restrict_permissions(output_path)
            return

        raise FormatNotSupportedError(i18n.t("err_file_format"))


def get_decrypt_output_path(input_path: str) -> str:
    """Decryption output path: strip the .enc suffix to restore the original name; append .dec if it does not end with .enc."""
    if input_path.lower().endswith(".enc"):
        return input_path[:-4]
    return input_path + ".dec"


def next_available_copy_name(target_path: str) -> str:
    """When the target exists, generate the next available copy name: xxx (1).ext, xxx (2).ext ..."""
    root, ext = os.path.splitext(target_path)
    i = 1
    while True:
        candidate = f"{root} ({i}){ext}"
        if not os.path.exists(candidate):
            return candidate
        i += 1


# ====================== Key rotation / re-encryption ======================

CIPHER_MODES = ("gcm", "cbc", "chacha20")


def _encrypt_text_with_mode(plain_text: str, password: str, mode: str = "gcm") -> str:
    if mode == "gcm":
        return AESGCMTool(password).encrypt(plain_text)
    if mode == "cbc":
        return AESCBCWithHMACTool(password).encrypt(plain_text)
    if mode == "chacha20":
        return ChaCha20Poly1305Tool(password).encrypt(plain_text)
    raise ValueError(i18n.t("err_cipher_mode"))


def reencrypt_text(ciphertext: str, old_password: str, new_password: str,
                   mode: str = "gcm") -> str:
    """Re-encrypt text in one step: decrypt with the old password (automatic format
    detection, so v2/legacy ciphertext is upgraded to the target format), then
    encrypt with the new password. No manual decrypt-then-encrypt required."""
    _validate_password_len(old_password)
    _validate_password_len(new_password)
    plain = try_text_decrypt(ciphertext, old_password)
    return _encrypt_text_with_mode(plain, new_password, mode)


def reencrypt_file(input_path: str, old_password: str, new_password: str,
                   output_path: Optional[str] = None) -> str:
    """Re-encrypt a file in one step (streaming, safe on large files).

    Decrypts to a temporary file, encrypts to the new output, then removes the
    temporary file. Default output: <original-stem>.enc (re-encrypt in place)."""
    if not os.path.isfile(input_path):
        raise ValueError(i18n.t("file_not_exist"))
    _validate_password_len(old_password)
    _validate_password_len(new_password)
    if output_path is None:
        output_path = get_decrypt_output_path(input_path) + ".enc"

    tmp_fd, tmp_path = tempfile.mkstemp(prefix="cryptpouch_reenc_", suffix=".tmp")
    os.close(tmp_fd)
    try:
        decrypt_file(input_path, tmp_path, old_password)
        encrypt_file(tmp_path, output_path, new_password)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    return output_path


# ====================== Batch encryption/decryption ======================

def _collect_targets(input_path: str, patterns: Optional[List[str]],
                     recursive: bool, for_encrypt: bool) -> List[str]:
    """Collect files to process: a single file, or a recursive directory scan
    filtered by fnmatch patterns. When encrypting, files already ending in .enc are
    skipped; when decrypting, only .enc files are considered."""
    norm = normalize_path(input_path)
    if os.path.isfile(norm):
        return [norm]
    if not os.path.isdir(norm):
        raise ValueError(i18n.t("file_not_exist"))

    matches: List[str] = []
    for root, dirs, files in os.walk(norm):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(root, name)
            is_enc = full.lower().endswith(".enc")
            if for_encrypt and is_enc:
                continue
            if not for_encrypt and not is_enc:
                continue
            if patterns:
                # Match the filter against the plain filename; when decrypting,
                # strip the .enc suffix so "*.txt" matches "a.txt.enc"
                match_name = name[:-4] if not for_encrypt and is_enc else name
                if not any(fnmatch.fnmatch(match_name, pat) for pat in patterns):
                    continue
            matches.append(full)
        if not recursive:
            break
    return matches


def batch_encrypt(path: str, password: str, pattern: Optional[str] = None,
                  recursive: bool = True) -> dict:
    """Encrypt every collected file in place as <file>.enc.

    Returns {"encrypted": [output paths], "failed": [(path, error)]}."""
    _validate_password_len(password)
    patterns = [p.strip() for p in pattern.split(",") if p.strip()] if pattern else None
    files = _collect_targets(path, patterns, recursive, for_encrypt=True)
    encrypted, failed = [], []
    for f in files:
        try:
            out = f + ".enc"
            encrypt_file(f, out, password)
            encrypted.append(out)
        except Exception as e:
            failed.append((f, str(e)))
    return {"encrypted": encrypted, "failed": failed}


def batch_decrypt(path: str, password: str, pattern: Optional[str] = None,
                  recursive: bool = True) -> dict:
    """Decrypt every collected .enc file in place (strips the .enc suffix).

    Note: an existing file with the target name is overwritten (batch restore).
    Returns {"decrypted": [output paths], "failed": [(path, error)]}."""
    _validate_password_len(password)
    patterns = [p.strip() for p in pattern.split(",") if p.strip()] if pattern else None
    files = _collect_targets(path, patterns, recursive, for_encrypt=False)
    decrypted, failed = [], []
    for f in files:
        try:
            out = get_decrypt_output_path(f)
            decrypt_file(f, out, password)
            decrypted.append(out)
        except Exception as e:
            failed.append((f, str(e)))
    return {"decrypted": decrypted, "failed": failed}


# ====================== Content type detection ======================

def detect_content_type(text: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Detect the type of the input.

    Returns (type key, encoding name or None, Base64 decode preview or None).
    Types: plain / b64 / aes_gcm / aes_cbc / binary.
    """
    stripped = text.strip()

    try:
        data = base64.b64decode(stripped, validate=True)
    except Exception:
        data = None

    if data is not None and data:
        # After prefix match, validate ciphertext structure length to avoid false positives from Base64 that happens to decode to the prefix
        # v3/GCM: prefix + salt16 + nonce12 + tag16; CBC: prefix + salt16 + iv16 + mac32 + at least 16 bytes of ciphertext
        gcm_min = len(PREFIX_AES_V3) + ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE
        cbc_min = len(PREFIX_AES_CBC_V2) + SALT_SIZE + IV_SIZE + HMAC_SIZE + 16

        if data.startswith(PREFIX_AES_V3) and len(data) >= gcm_min:
            return "analyze_type_aes_gcm", None, None
        if data.startswith(PREFIX_AES_GCM_V2) and len(data) >= gcm_min:
            return "analyze_type_aes_gcm", None, None
        if data.startswith(PREFIX_AES_CBC_V2) and len(data) >= cbc_min:
            return "analyze_type_aes_cbc", None, None
        chacha_min = len(PREFIX_CHACHA20) + ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE
        if data.startswith(PREFIX_CHACHA20) and len(data) >= chacha_min:
            return "analyze_type_chacha20", None, None

        dec_text, enc = detect_decode(data)
        score = _encoding_score(dec_text, enc)
        if score >= max(1, len(dec_text) * 0.5):
            return "analyze_type_b64", enc, dec_text

        # Unreadable: if the length matches legacy AES structure (salt16+nonce12+tag16=44,
        # CBC additionally needs a 16-byte IV and at least 16 bytes of ciphertext), treat as likely legacy ciphertext
        if len(data) >= 44:
            return "analyze_type_aes_legacy", None, None
        return "analyze_type_binary", None, None

    # Not Base64: check whether it is readable text
    if stripped and all(
        ord(c) >= 0x20 and ord(c) != 0x7F
        for c in stripped
    ):
        return "analyze_type_plain", "unicode", None
    return "analyze_type_binary", None, None


def analyze_and_show(text: str):
    """Print the analysis report; ask whether to attempt decryption for AES ciphertext."""
    ctype, enc, preview = detect_content_type(text)
    printer.info(i18n.t("analyze_title"))
    print(i18n.t(ctype))
    if enc:
        print(i18n.t("analyze_encoding", enc=enc))
    if preview is not None:
        printer.info(i18n.t("auto_b64_detected"))
        print(preview)
    if ctype in ("analyze_type_aes_gcm", "analyze_type_aes_cbc", "analyze_type_aes_legacy", "analyze_type_chacha20"):
        if _safe_input(i18n.t("analyze_try_decrypt")).strip().lower() == "y":
            _try_all_aes_decrypt(text)


# ====================== Automatic decryption ======================

def auto_decrypt_text(enc_str: str):
    try:
        res = b64_decode(enc_str)
        printer.ok(i18n.t("auto_b64_detected"))
        print(res)

        force = _safe_input(i18n.t("auto_force_aes")).strip().lower()
        if force == "y":
            _try_all_aes_decrypt(enc_str)
        return
    except (base64.binascii.Error, UnicodeDecodeError):
        pass

    printer.info(i18n.t("auto_try_aes"))
    _try_all_aes_decrypt(enc_str)


def _peek_pack_prefix(enc_str: str) -> bytes:
    """Best-effort Base64 decode of a ciphertext pack to inspect its format prefix.
    Returns b'' on failure so callers can fall back to legacy probing."""
    try:
        return _decode_pack_b64(enc_str)
    except (base64.binascii.Error, ValueError):
        return b""


def _try_text_decrypt_family(enc_str: str, pwd: str) -> Tuple[str, str]:
    """Decrypt text with automatic cipher-family routing; returns (plaintext, family).

    Prefixed ciphertext ($CP3$/$AG2$/$AC2$/$CC1$) is routed directly to its own
    decoder - this avoids expensive legacy probing on the wrong family. Prefixless
    legacy ciphertext falls back to the GCM then CBC compatibility matrices."""
    pack = _peek_pack_prefix(enc_str)
    if pack.startswith(PREFIX_CHACHA20):
        return ChaCha20Poly1305Tool(pwd).decrypt(enc_str), "chacha20"
    if pack.startswith(PREFIX_AES_CBC_V2):
        return AESCBCWithHMACTool(pwd).decrypt(enc_str), "cbc"
    if pack.startswith((PREFIX_AES_V3, PREFIX_AES_GCM_V2)):
        return AESGCMTool(pwd).decrypt(enc_str), "gcm"

    # Prefixless: GCM compatibility probes first, then CBC compatibility probes
    try:
        return AESGCMTool(pwd).decrypt(enc_str), "gcm"
    except (PasswordError, CipherCorruptedError):
        pass
    return AESCBCWithHMACTool(pwd).decrypt(enc_str), "cbc"


def try_text_decrypt(enc_str: str, pwd: str) -> str:
    """Decrypt text with automatic cipher-family routing (returns the plaintext)."""
    plain, _ = _try_text_decrypt_family(enc_str, pwd)
    return plain


def _try_all_aes_decrypt(enc_str: str):
    for i in range(MAX_PASSWORD_ATTEMPTS):
        pwd = getpass.getpass(i18n.t("decrypt_pwd"))
        try:
            plain, family = _try_text_decrypt_family(enc_str, pwd)
        except (PasswordError, CipherCorruptedError) as e:
            printer.fail(str(e))
            if i < MAX_PASSWORD_ATTEMPTS - 1:
                printer.warn(i18n.t("attempts_left", left=MAX_PASSWORD_ATTEMPTS - i - 1))
            continue
        except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
            printer.fail(str(e))
            return
        except Exception as e:
            _handle_unexpected_error(e)
            return
        ok_key = {"gcm": "auto_gcm_ok", "cbc": "auto_cbc_ok", "chacha20": "auto_chacha_ok"}[family]
        printer.ok(i18n.t(ok_key))
        print(plain)
        return
    printer.fail(i18n.t("attempts_exceeded"))


# ====================== Password input with confirmation ======================

MAX_PASSWORD_ATTEMPTS = 5


def _safe_input(prompt: str = "", max_len: int = 10 * 1024 * 1024) -> str:
    """_safe_input() with a length cap (guards against pasted-buffer DoS)."""
    value = input(prompt)
    if max_len and len(value) > max_len:
        raise ValueError(i18n.t("input_too_long", max=max_len))
    return value


def _validate_password_len(password: str) -> None:
    """Enforce the configured password length cap at every crypto entry point."""
    if len(password) > PASSWORD_MAX_LEN:
        raise ValueError(i18n.t("pwd_too_long", max=PASSWORD_MAX_LEN))


def _restrict_permissions(path: str) -> None:
    """Best-effort POSIX 0600 on sensitive outputs (no-op on Windows)."""
    try:
        if os.name != "nt":
            os.chmod(path, 0o600)
    except OSError:
        pass


def _text_decrypt_with_retry(attempt, max_attempts: int = MAX_PASSWORD_ATTEMPTS) -> None:
    """Run attempt(password) with user-supplied passwords, retrying on password/cipher errors."""
    for i in range(max_attempts):
        pwd = getpass.getpass(i18n.t("decrypt_pwd"))
        try:
            res = attempt(pwd)
        except (PasswordError, CipherCorruptedError) as e:
            printer.fail(str(e))
            if i < max_attempts - 1:
                printer.warn(i18n.t("attempts_left", left=max_attempts - i - 1))
            continue
        except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
            printer.fail(str(e))
            return
        except Exception as e:
            _handle_unexpected_error(e)
            return
        printer.ok(i18n.t("success"))
        print(res)
        return
    printer.fail(i18n.t("attempts_exceeded"))


# ====================== Password input with confirmation ======================

def _handle_unexpected_error(e: Exception) -> None:
    """Handle unexpected exceptions: show a short message; print the full traceback
    only when CRYPTPOUCH_DEBUG=1 (keeps internal details out of normal output)."""
    if os.environ.get("CRYPTPOUCH_DEBUG") == "1":
        import traceback
        traceback.print_exception(type(e), e, e.__traceback__)
    printer.fail(str(e))


def get_password_with_confirm(prompt_key: str = "encrypt_pwd") -> str:
    """Prompt for a password with confirmation; re-prompt when they differ (prevents typos on the encryption path)."""
    while True:
        pwd = getpass.getpass(i18n.t(prompt_key))
        if len(pwd) > PASSWORD_MAX_LEN:
            printer.fail(i18n.t("pwd_too_long", max=PASSWORD_MAX_LEN))
            continue
        confirm = getpass.getpass(i18n.t("confirm_pwd"))
        # Constant-time comparison: same discipline everywhere passwords are compared
        if hmac.compare_digest(pwd, confirm):
            return pwd
        printer.warn(i18n.t("pwd_mismatch"))


# ====================== Clipboard helper ======================

def copy_to_clipboard(text: str):
    try:
        import pyperclip
        pyperclip.copy(text)
        printer.ok(i18n.t("copy_done"))
    except Exception:
        printer.warn(i18n.t("copy_fail"))


# ====================== Menu ======================

def show_menu():
    printer.info(i18n.t("menu_title"))
    print("1. AES-GCM 加密" if i18n.lang == "zh" else "1. AES-GCM Encrypt")
    print("2. AES-GCM 解密" if i18n.lang == "zh" else "2. AES-GCM Decrypt")
    print("3. AES-CBC 加密" if i18n.lang == "zh" else "3. AES-CBC Encrypt")
    print("4. AES-CBC 解密" if i18n.lang == "zh" else "4. AES-CBC Decrypt")
    print("5. 自动识别解密" if i18n.lang == "zh" else "5. Auto Decrypt")
    print("6. Base64 编码" if i18n.lang == "zh" else "6. Base64 Encode")
    print("7. Base64 解码" if i18n.lang == "zh" else "7. Base64 Decode")
    print("8. 文本哈希" if i18n.lang == "zh" else "8. Text Hash")
    print("9. 文件哈希" if i18n.lang == "zh" else "9. File Hash")
    print("10. 随机密码生成" if i18n.lang == "zh" else "10. Random Password")
    print("11. 密码强度检测" if i18n.lang == "zh" else "11. Password Strength")
    print("12. RSA 生成密钥对" if i18n.lang == "zh" else "12. RSA Generate Keys")
    print("13. RSA 加密" if i18n.lang == "zh" else "13. RSA Encrypt")
    print("14. RSA 解密" if i18n.lang == "zh" else "14. RSA Decrypt")
    print("15. 文件加密" if i18n.lang == "zh" else "15. File Encrypt")
    print("16. 文件解密" if i18n.lang == "zh" else "16. File Decrypt")

    if importlib.util.find_spec("qrcode") and importlib.util.find_spec("PIL"):
        print("17. 生成二维码" if i18n.lang == "zh" else "17. Generate QR Code")
    else:
        print("17. 生成二维码（需安装 qrcode pillow）" if i18n.lang == "zh" else "17. Generate QR Code (needs qrcode pillow)")

    if importlib.util.find_spec("pyzbar") and importlib.util.find_spec("PIL"):
        print("18. 解析二维码" if i18n.lang == "zh" else "18. Decode QR Code")
    else:
        print("18. 解析二维码（需安装 pyzbar pillow）" if i18n.lang == "zh" else "18. Decode QR Code (needs pyzbar pillow)")

    print("19. 自动识别内容类型" if i18n.lang == "zh" else "19. Analyze Content Type")
    print("20. ChaCha20-Poly1305 加密" if i18n.lang == "zh" else "20. ChaCha20-Poly1305 Encrypt")
    print("21. ChaCha20-Poly1305 解密" if i18n.lang == "zh" else "21. ChaCha20-Poly1305 Decrypt")
    print("22. 密钥轮转（文本）" if i18n.lang == "zh" else "22. Re-encrypt Text")
    print("23. 密钥轮转（文件）" if i18n.lang == "zh" else "23. Re-encrypt File")
    print("24. 批量加密（目录/文件）" if i18n.lang == "zh" else "24. Batch Encrypt (dir/file)")
    print("25. 批量解密（目录/文件）" if i18n.lang == "zh" else "25. Batch Decrypt (dir/file)")
    print("0. 退出" if i18n.lang == "zh" else "0. Exit")


def menu_loop():
    interrupt_count = 0  # consecutive Ctrl+C counter (exit on two consecutive presses)
    while True:
        show_menu()
        choice = _safe_input(i18n.t("input_choice")).strip()
        interrupt_count = 0  # reset the interrupt counter after a normal input

        try:
            if choice == "1":
                pwd = get_password_with_confirm("encrypt_pwd")
                content = _safe_input(i18n.t("input_plain"))
                tool = AESGCMTool(pwd)
                result = tool.encrypt(content)
                printer.ok(i18n.t("success"))
                print(result)
                copy_to_clipboard(result)

            elif choice == "2":
                enc_str = _safe_input(i18n.t("input_cipher"))
                _text_decrypt_with_retry(lambda pwd: AESGCMTool(pwd).decrypt(enc_str))

            elif choice == "3":
                pwd = get_password_with_confirm("encrypt_pwd")
                content = _safe_input(i18n.t("input_plain"))
                tool = AESCBCWithHMACTool(pwd)
                result = tool.encrypt(content)
                printer.ok(i18n.t("success"))
                print(result)
                copy_to_clipboard(result)

            elif choice == "4":
                enc_str = _safe_input(i18n.t("input_cipher"))
                _text_decrypt_with_retry(lambda pwd: AESCBCWithHMACTool(pwd).decrypt(enc_str))

            elif choice == "5":
                text = _safe_input(i18n.t("input_cipher"))
                analyze_and_show(text)

            elif choice == "6":
                content = _safe_input(i18n.t("input_plain"))
                printer.ok(i18n.t("success"))
                print(b64_encode(content))

            elif choice == "7":
                b64_text = _safe_input(i18n.t("input_cipher"))
                try:
                    plain = b64_decode(b64_text)
                    printer.ok(i18n.t("success"))
                    print(plain)
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "8":
                content = _safe_input(i18n.t("input_plain"))
                alg = _safe_input(i18n.t("alg_prompt")).strip().lower() or "sha256"
                try:
                    result = calc_hash(content.encode("utf-8"), alg)
                    printer.ok(i18n.t("success"))
                    print(result)
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "9":
                file_path = normalize_path(_safe_input(i18n.t("file_path")))
                if not os.path.isfile(file_path):
                    printer.fail(i18n.t("file_not_exist"))
                    continue
                alg = _safe_input(i18n.t("alg_prompt")).strip().lower() or "sha256"
                try:
                    result = calc_file_hash(file_path, alg)
                    printer.ok(i18n.t("success"))
                    print(result)
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "10":
                len_str = _safe_input(i18n.t("len_prompt")).strip()
                pwd_len = int(len_str) if len_str.isdigit() and int(len_str) >= 8 else 16
                pwd = generate_random_password(pwd_len)
                printer.ok(i18n.t("success"))
                print(pwd)
                copy_to_clipboard(pwd)

            elif choice == "11":
                pwd = _safe_input(i18n.t("pwd_input_prompt"))
                level, tips = check_password_strength(pwd)
                printer.info(i18n.t("strength_label", level=level))
                for tip in tips:
                    printer.warn(tip)

            elif choice == "12":
                printer.info(i18n.t("rsa_gen_keys"))
                bits_str = _safe_input(i18n.t("rsa_bits_prompt")).strip()
                bits = int(bits_str) if bits_str.isdigit() else RSA_KEY_BITS
                if bits not in (2048, 3072, 4096):
                    printer.fail(i18n.t("rsa_bits_invalid"))
                    continue
                use_pass = _safe_input(i18n.t("rsa_protect_prompt")).strip().lower()
                passphrase = None
                if use_pass == "y":
                    passphrase = get_password_with_confirm("rsa_enter_passphrase")
                priv, pub = rsa_generate_keys(passphrase, key_bits=bits)
                priv_path = os.path.join(SCRIPT_DIR, "rsa_private.pem")
                pub_path = os.path.join(SCRIPT_DIR, "rsa_public.pem")
                with open(priv_path, "wb") as f:
                    f.write(priv)
                _restrict_permissions(priv_path)
                with open(pub_path, "wb") as f:
                    f.write(pub)
                printer.ok(i18n.t("success"))
                print(i18n.t("rsa_private_label", path=priv_path))
                print(i18n.t("rsa_public_label", path=pub_path))

            elif choice == "13":
                pub_path = normalize_path(_safe_input(i18n.t("rsa_pub_path_prompt")))
                text = _safe_input(i18n.t("rsa_enter_text"))
                try:
                    result = rsa_encrypt(pub_path, text)
                    printer.ok(i18n.t("success"))
                    print(result)
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "14":
                pri_path = normalize_path(_safe_input(i18n.t("rsa_pri_path_prompt")))
                b64_text = _safe_input(i18n.t("rsa_enter_cipher"))
                passphrase = None
                if _safe_input(i18n.t("rsa_has_passphrase")).strip().lower() == "y":
                    passphrase = getpass.getpass(i18n.t("rsa_enter_passphrase"))
                try:
                    result = rsa_decrypt(pri_path, b64_text, passphrase)
                    printer.ok(i18n.t("success"))
                    print(result)
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "15":
                input_path = normalize_path(_safe_input(i18n.t("file_path")))
                if not os.path.isfile(input_path):
                    printer.fail(i18n.t("file_not_exist"))
                    continue
                pwd = get_password_with_confirm("encrypt_pwd")
                output_path = input_path + ".enc"
                encrypt_file(input_path, output_path, pwd)
                printer.ok(i18n.t("file_encrypted_to", path=output_path))

            elif choice == "16":
                input_path = normalize_path(_safe_input(i18n.t("file_path")))
                if not os.path.isfile(input_path):
                    printer.fail(i18n.t("file_not_exist"))
                    continue
                output_path = get_decrypt_output_path(input_path)
                if os.path.exists(output_path):
                    confirm = _safe_input(i18n.t("target_exists")).strip().lower()
                    if confirm != "y":
                        output_path = next_available_copy_name(output_path)
                        printer.warn(i18n.t("kept_original") + f" {output_path}")
                for i in range(MAX_PASSWORD_ATTEMPTS):
                    pwd = getpass.getpass(i18n.t("decrypt_pwd"))
                    try:
                        decrypt_file(input_path, output_path, pwd)
                    except (PasswordError, CipherCorruptedError) as e:
                        printer.fail(str(e))
                        if i < MAX_PASSWORD_ATTEMPTS - 1:
                            printer.warn(i18n.t("attempts_left", left=MAX_PASSWORD_ATTEMPTS - i - 1))
                        continue
                    except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                        printer.fail(str(e))
                        break
                    except Exception as e:
                        _handle_unexpected_error(e)
                        break
                    printer.ok(i18n.t("file_decrypted_to", path=output_path))
                    break
                else:
                    printer.fail(i18n.t("attempts_exceeded"))

            elif choice == "17":
                if not (importlib.util.find_spec("qrcode") and importlib.util.find_spec("PIL")):
                    printer.fail(i18n.t("qr_missing_pkg"))
                    continue
                text = _safe_input(i18n.t("qr_content_prompt"))
                save = _safe_input(i18n.t("qr_save_prompt")).strip().lower()
                save_path = None
                if save == "y":
                    save_path = _safe_input(i18n.t("qr_filename_prompt")).strip()
                    if save_path and not os.path.isabs(save_path):
                        save_path = os.path.join(SCRIPT_DIR, save_path)
                try:
                    generate_qr(text, save_path)
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "18":
                if not (importlib.util.find_spec("pyzbar") and importlib.util.find_spec("PIL")):
                    printer.fail(i18n.t("zb_missing_pkg"))
                    continue
                img_path = normalize_path(_safe_input(i18n.t("file_path")))
                if not os.path.isfile(img_path):
                    printer.fail(i18n.t("file_not_exist"))
                    continue
                try:
                    results = decode_qr(img_path)
                    if results:
                        printer.ok(i18n.t("success"))
                        for item in results:
                            print(item)
                    else:
                        printer.fail(i18n.t("qr_no_content"))
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "19":
                text = _safe_input(i18n.t("analyze_input"))
                analyze_and_show(text)

            elif choice == "20":
                pwd = get_password_with_confirm("encrypt_pwd")
                content = _safe_input(i18n.t("input_plain"))
                tool = ChaCha20Poly1305Tool(pwd)
                result = tool.encrypt(content)
                printer.ok(i18n.t("success"))
                print(result)
                copy_to_clipboard(result)

            elif choice == "21":
                enc_str = _safe_input(i18n.t("input_cipher"))
                _text_decrypt_with_retry(lambda pwd: ChaCha20Poly1305Tool(pwd).decrypt(enc_str))

            elif choice == "22":
                enc_str = _safe_input(i18n.t("input_cipher"))
                old_pwd = getpass.getpass(i18n.t("reencrypt_old_pwd"))
                new_pwd = get_password_with_confirm("reencrypt_new_pwd")
                mode = _safe_input(i18n.t("reencrypt_mode_prompt")).strip().lower() or "gcm"
                if mode not in CIPHER_MODES:
                    printer.fail(i18n.t("err_cipher_mode"))
                    continue
                try:
                    result = reencrypt_text(enc_str, old_pwd, new_pwd, mode)
                    printer.ok(i18n.t("reencrypt_done"))
                    print(result)
                    copy_to_clipboard(result)
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "23":
                input_path = normalize_path(_safe_input(i18n.t("file_path")))
                if not os.path.isfile(input_path):
                    printer.fail(i18n.t("file_not_exist"))
                    continue
                old_pwd = getpass.getpass(i18n.t("reencrypt_old_pwd"))
                new_pwd = get_password_with_confirm("reencrypt_new_pwd")
                try:
                    out = reencrypt_file(input_path, old_pwd, new_pwd)
                    printer.ok(i18n.t("reencrypt_done"))
                    print(i18n.t("reencrypt_output", path=out))
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "24":
                target = normalize_path(_safe_input(i18n.t("batch_path_prompt")))
                pattern = _safe_input(i18n.t("batch_pattern_prompt")).strip()
                pwd = get_password_with_confirm("encrypt_pwd")
                try:
                    result = batch_encrypt(target, pwd, pattern or None)
                    printer.ok(i18n.t("batch_encrypted_n", n=len(result["encrypted"])))
                    for path, err in result["failed"]:
                        printer.fail(f"{path}: {err}")
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "25":
                printer.warn(i18n.t("batch_overwrite_hint"))
                target = normalize_path(_safe_input(i18n.t("batch_path_prompt")))
                pattern = _safe_input(i18n.t("batch_pattern_prompt")).strip()
                pwd = getpass.getpass(i18n.t("decrypt_pwd"))
                try:
                    result = batch_decrypt(target, pwd, pattern or None)
                    printer.ok(i18n.t("batch_decrypted_n", n=len(result["decrypted"])))
                    for path, err in result["failed"]:
                        printer.fail(f"{path}: {err}")
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "0":
                confirm = _safe_input(i18n.t("exit_confirm")).strip().lower()
                if confirm == "y":
                    printer.info(i18n.t("bye"))
                    break

            else:
                printer.warn(i18n.t("invalid_choice"))

        except KeyboardInterrupt:
            print()
            if interrupt_count > 0:
                printer.info(i18n.t("bye"))
                sys.exit(0)
            interrupt_count = 1
            printer.warn(i18n.t("ctrl_c_hint"))
        except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
            printer.fail(str(e))
        except MemoryError:
            printer.fail(i18n.t("mem_error"))
            raise
        except Exception as e:
            _handle_unexpected_error(e)


# ====================== Command-line mode ======================

def cli_mode():
    # Pre-parse --lang so the help text follows the selected language
    # (default comes from the user config / CRYPTPOUCH_LANG when set)
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", choices=["zh", "en"], default=CONFIG.get("lang") or "zh")
    ns, _ = pre.parse_known_args()

    global i18n, printer
    i18n = I18n(ns.lang)
    printer = Printer(i18n)

    parser = argparse.ArgumentParser(description=i18n.t("cli_desc"))
    parser.add_argument("-e", "--encrypt", help=i18n.t("cli_e_help"))
    parser.add_argument("-d", "--decrypt", help=i18n.t("cli_d_help"))
    parser.add_argument("-p", "--password", help=i18n.t("cli_p_help"))
    parser.add_argument("--password-file", help=i18n.t("cli_password_file_help"))
    parser.add_argument("-f", "--file", action="store_true", help=i18n.t("cli_f_help"))
    parser.add_argument("-o", "--output", help=i18n.t("cli_o_help"))
    parser.add_argument("--hash", help=i18n.t("cli_hash_help"))
    parser.add_argument("--cipher", choices=list(CIPHER_MODES), default="gcm", help=i18n.t("cli_cipher_help"))
    parser.add_argument("--lang", choices=["zh", "en"], default=CONFIG.get("lang") or "zh", help=i18n.t("cli_lang_help"))
    parser.add_argument("--version", action="version", version="2.9.0")

    args = parser.parse_args()

    if args.hash:
        target = args.encrypt or args.decrypt
        if not target or not os.path.isfile(target):
            printer.fail(i18n.t("file_not_exist"))
            sys.exit(1)
        try:
            h = calc_file_hash(target, args.hash)
            print(h)
        except Exception as e:
            printer.fail(str(e))
        return

    # CLI mode also checks core dependencies
    missing_core, _ = check_dependencies()
    if missing_core:
        printer.fail(i18n.t("core_deps_missing"))
        printer.info(i18n.t("missing_list") + ", ".join(missing_core))
        printer.info(i18n.t("install_cmd_global") + " pip install " + " ".join(missing_core))
        sys.exit(1)

    if args.encrypt or args.decrypt:
        if args.password_file:
            # Read the password from a file (avoid exposing it in the process list)
            try:
                with open(args.password_file, "r", encoding="utf-8") as f:
                    pwd = f.read().strip()
                if len(pwd) > PASSWORD_MAX_LEN:
                    printer.fail(i18n.t("pwd_too_long", max=PASSWORD_MAX_LEN))
                    sys.exit(1)
            except Exception as e:
                printer.fail(str(e))
                sys.exit(1)
        elif args.password:
            if len(args.password) > PASSWORD_MAX_LEN:
                printer.fail(i18n.t("pwd_too_long", max=PASSWORD_MAX_LEN))
                sys.exit(1)
            pwd = args.password
            # Warn about process-list exposure when -p is used (non-blocking for script compatibility)
            printer.warn(i18n.t("cli_p_warn"))
        elif args.encrypt:
            # CLI encryption without -p: prompt interactively and confirm the password
            pwd = get_password_with_confirm("encrypt_pwd")
        else:
            pwd = getpass.getpass(i18n.t("decrypt_pwd"))
            if len(pwd) > PASSWORD_MAX_LEN:
                printer.fail(i18n.t("pwd_too_long", max=PASSWORD_MAX_LEN))
                sys.exit(1)
        target = args.encrypt or args.decrypt

        try:
            if args.file:
                if args.encrypt:
                    out = args.output or target + ".enc"
                    encrypt_file(target, out, pwd)
                    printer.ok(i18n.t("cli_file_encrypted"))
                else:
                    if args.output:
                        out = args.output
                    else:
                        out = get_decrypt_output_path(target)
                        if os.path.exists(out):
                            printer.fail(i18n.t("cli_output_exists"))
                            return
                    decrypt_file(target, out, pwd)
                    printer.ok(i18n.t("cli_file_decrypted", path=out))
            else:
                if args.encrypt:
                    print(_encrypt_text_with_mode(target, pwd, args.cipher))
                else:
                    print(try_text_decrypt(target, pwd))
        except Exception as e:
            printer.fail(str(e))
        return


# ====================== Startup flow ======================

def select_language():
    print("1. 中文")
    print("2. English")
    choice = _safe_input("请选择语言 / Select language: ").strip()
    if choice == "2":
        return "en"
    return "zh"


def main():
    global i18n, printer

    # With command-line arguments, enter CLI mode directly (--lang or default), no interactive prompts
    if len(sys.argv) > 1:
        cli_mode()
        return

    # Default language can be fixed via config.json ("lang") or CRYPTPOUCH_LANG;
    # otherwise ask interactively
    lang = CONFIG.get("lang") or select_language()
    i18n = I18n(lang)
    printer = Printer(i18n)

    printer.info(i18n.t("welcome"))
    printer.info(i18n.t("usage_tip"))
    printer.warn(i18n.t("legal_tip"))

    missing_core, missing_optional = check_dependencies()

    if missing_core:
        printer.fail(i18n.t("core_deps_missing"))
        printer.info(i18n.t("missing_list") + ", ".join(missing_core))
        install_packages(missing_core, i18n)

    if missing_optional:
        printer.warn(i18n.t("optional_deps_missing"))
        printer.info(i18n.t("missing_list") + ", ".join(missing_optional))

    try:
        menu_loop()
    except KeyboardInterrupt:
        print()
        printer.info(i18n.t("bye"))
        sys.exit(0)


if __name__ == "__main__":
    main()
