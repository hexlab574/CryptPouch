#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AES256 综合加密工具箱
版本：2.7.2
许可证：MIT
说明：仅供学习研究与个人本地使用。
"""

import base64
import getpass
import hashlib
import importlib.util
import os
import secrets
import string
import subprocess
import sys
import time
import argparse
from typing import Optional, Tuple, List


# ====================== 控制台编码兼容 ======================
# 修复：Windows 中文系统默认 GBK 代码页，无法编码颜文字（如 ｡•́︿•̀｡），
# 导致 print 抛出 UnicodeEncodeError，程序在选择语言后崩溃。

def _setup_console_encoding():
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    # Windows 下把控制台代码页切换为 UTF-8(65001)，保证中文与颜文字正常显示
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleCP(65001)
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass


_setup_console_encoding()


# ====================== 双语提示 ======================

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


# ====================== 输出工具：无图案，保留颜文字 ======================

class Printer:
    def __init__(self, i18n: I18n):
        self.i18n = i18n

    def info(self, msg: str):
        print(f"[提示] {msg}" if self.i18n.lang == "zh" else f"[Info] {msg}")

    def ok(self, msg: str):
        print(f"[成功] {msg} " if self.i18n.lang == "zh" else f"[OK] {msg} ")

    def warn(self, msg: str):
        print(f"[警告] {msg} (｡•́︿•̀｡)" if self.i18n.lang == "zh" else f"[Warning] {msg} (｡•́︿•̀｡)")

    def fail(self, msg: str):
        print(f"[错误] {msg} (╥﹏╥)" if self.i18n.lang == "zh" else f"[Error] {msg} (╥﹏╥)")


# ====================== 全局对象 ======================

i18n = I18n()
printer = Printer(i18n)


# ====================== 依赖检测与自动安装（已修复） ======================

# key: pip 包名；value: Python 实际导入的模块名
CORE_PACKAGES = {
    "pycryptodome": "Crypto",
    "argon2-cffi": "argon2",  # v3 格式的 Argon2id 密钥派生
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

    confirm = input(i18n.t("ask_install")).strip().lower()
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
            # 用子进程方式重启，避免 os.execv 绕过清理逻辑
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


# ====================== 常量配置 ======================

# 脚本所在目录：生成的密钥、二维码等文件默认写到这里（避免商店版 Python
# 双击运行时工作目录不可写导致的 Permission denied）
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_ITERATIONS = 600_000
# 老版独立工具（文本加密工具.py）使用 100000 次迭代且无格式前缀；
# 解密无前缀旧版密文时需回退尝试该迭代次数
LEGACY_ITERATIONS = 100_000

# 无前缀旧版密文的兼容探测矩阵：(PBKDF2 迭代次数, HMAC 哈希名, 密钥字节长度)
# 按命中概率排序，覆盖 CryptPouch 旧版、老版工具、常见简易工具（SHA1/低迭代/AES-128）
LEGACY_DECRYPT_PROBES = [
    (DEFAULT_ITERATIONS, "SHA256", 32),  # CryptPouch 旧版格式
    (LEGACY_ITERATIONS, "SHA256", 32),   # 文本加密工具.py（老版工具）
    (100_000, "SHA1", 32),               # 常见工具（PBKDF2 默认 HMAC-SHA1）
    (10_000, "SHA256", 32),
    (100_000, "MD5", 32),
    (1_000, "SHA256", 32),               # 简易工具/教程示例的默认值
    (10_000, "SHA1", 32),
    (1_000, "SHA1", 32),
    (100_000, "SHA256", 16),             # AES-128 变体
]
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 32
# RSA 密钥长度（2048 位为当前业界推荐最低强度）
RSA_KEY_BITS = 2048
# 密码长度上限：防止超长密码导致 Argon2/PBKDF2 计算异常缓慢（拒绝服务面）
PASSWORD_MAX_LEN = 128
# 密码强度评分阈值（可调）
SCORE_STRONG = 5
SCORE_MEDIUM = 3
# 二维码内容长度上限（可调）
QR_MAX_LEN = 5000

PREFIX_AES_GCM_V2 = b"$AG2$"
PREFIX_AES_CBC_V2 = b"$AC2$"
# v3：Argon2id 密钥派生 + AES-256-GCM（正式版本化格式）
PREFIX_AES_V3 = b"$CP3$"

# Argon2id 参数（OWASP 推荐档：3 轮 / 64 MiB / 4 并行）
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65536   # 64 MiB
ARGON2_PARALLELISM = 4
ARGON2_SALT_SIZE = 16
ARGON2_HASH_LEN = 32             # AES-256


# ====================== 自定义异常 ======================

class CryptoToolError(Exception):
    pass


class CipherCorruptedError(CryptoToolError):
    pass


class PasswordError(CryptoToolError):
    pass


class FormatNotSupportedError(CryptoToolError):
    pass


# ====================== 基础工具函数 ======================

def normalize_path(path_str: str) -> str:
    """规范化用户输入的路径：去除拖拽引号/空格、解析 ../ 与 . 序列。

    说明：本工具是本地单用户程序，加解密的目标路径由用户本人提供，
    攻击者即用户自身，因此不设置目录白名单（否则无法加密任意位置文件）。
    此处仅做：拒绝 NUL 等非法字符、解析冗余的 . 与 ..，保证后续文件操作
    拿到的是干净的绝对化路径。"""
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
    # 验证所有填充字节的值都等于填充长度（防 Padding Oracle 类错误）
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("PKCS7 padding error")
    return data[:-padding_len]


def _get_hash_module(name: str):
    """按名称返回 Crypto.Hash 模块，未知名称回退 SHA256。"""
    from Crypto.Hash import SHA256, SHA1, MD5
    return {"SHA256": SHA256, "SHA1": SHA1, "MD5": MD5}.get(name, SHA256)


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS,
               hash_module=None, dk_len: int = 32) -> bytes:
    """PBKDF2 密钥派生。hash_module 默认 SHA256；dk_len 决定 AES-128/256。"""
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
    """Argon2id 密钥派生（内存硬函数，抗 GPU/ASIC 并行破解）。"""
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
    """派生 CBC 加解密密钥对：主密钥经 HKDF 拆分为加密密钥与 MAC 密钥
    （密钥分离原则，Encrypt-then-MAC 构造）。"""
    from Crypto.Protocol.KDF import HKDF

    master = derive_key(password, salt, iterations)
    h = _get_hash_module("SHA256")
    enc_key = HKDF(master, 32, salt, h, context=b"CryptPouch-enc")
    mac_key = HKDF(master, 32, salt, h, context=b"CryptPouch-mac")
    return enc_key, mac_key


def _note_legacy_params(iterations: int, hash_name: str, dk_len: int):
    """解密旧版密文命中的兼容参数非默认值时，提示用户匹配到的参数。"""
    if iterations != DEFAULT_ITERATIONS or hash_name != "SHA256" or dk_len != 32:
        printer.info(i18n.t("legacy_decrypt_hint", iters=iterations, hash=hash_name))


def _is_readable_text(raw: bytes) -> bool:
    """粗略判断字节是否为可读文本（用于 CBC 无认证探测的误报过滤）。
    增加最小长度门槛：极短明文（1~3 字节）本就难以可靠区分，直接判为不可读，
    避免二进制数据因阈值过低被误认为有效明文。"""
    if len(raw) < 4:
        return False
    text, enc = detect_decode(raw)
    return _encoding_score(text, enc) >= max(1, len(text) * 0.5)


# ====================== AES-GCM 加解密 ======================

class AESGCMTool:
    def __init__(self, password: str, iterations: int = DEFAULT_ITERATIONS):
        self.password = password
        self.iterations = iterations

    def encrypt(self, plain_text: str) -> str:
        """v3 格式：Argon2id 派生 + AES-256-GCM，前缀 $CP3$。"""
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes

        salt = get_random_bytes(ARGON2_SALT_SIZE)
        nonce = get_random_bytes(NONCE_SIZE)
        key = derive_argon2_key(self.password, salt)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode("utf-8"))

        pack = PREFIX_AES_V3 + salt + nonce + tag + ciphertext
        return base64.b64encode(pack).decode("utf-8")

    def decrypt(self, b64_str: str) -> str:
        from Crypto.Cipher import AES

        try:
            pack = _decode_pack_b64(b64_str)
        except base64.binascii.Error:
            raise CipherCorruptedError(i18n.t("err_b64_corrupted"))

        # v3：Argon2id + $CP3$ 前缀（正式格式）
        if pack.startswith(PREFIX_AES_V3):
            data = pack[len(PREFIX_AES_V3):]
            if len(data) < ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE:
                raise CipherCorruptedError(i18n.t("err_len_invalid"))
            salt = data[:ARGON2_SALT_SIZE]
            nonce = data[ARGON2_SALT_SIZE:ARGON2_SALT_SIZE + NONCE_SIZE]
            tag = data[ARGON2_SALT_SIZE + NONCE_SIZE:ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE]
            ciphertext = data[ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE:]

            key = derive_argon2_key(self.password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            try:
                raw = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                raise PasswordError(i18n.t("err_pwd_or_tamper"))
            return _decode_with_hint(raw)

        # v2：PBKDF2 600k + $AG2$ 前缀（快速路径）
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
            # 带版本前缀：固定使用当前迭代次数（快速路径）
            key = derive_key(self.password, salt, self.iterations)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            try:
                raw = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                raise PasswordError(i18n.t("err_pwd_or_tamper"))
            return _decode_with_hint(raw)

        # 无前缀旧版：遍历兼容探测矩阵（迭代次数 × 哈希 × 密钥长度）
        for iterations, hash_name, dk_len in LEGACY_DECRYPT_PROBES:
            key = derive_key(self.password, salt, iterations, _get_hash_module(hash_name), dk_len)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            try:
                raw = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                continue
            _note_legacy_params(iterations, hash_name, dk_len)
            return _decode_with_hint(raw)

        raise PasswordError(i18n.t("err_pwd_or_tamper"))


# ====================== AES-CBC + HMAC 加解密 ======================

class AESCBCWithHMACTool:
    def __init__(self, password: str, iterations: int = DEFAULT_ITERATIONS):
        self.password = password
        self.iterations = iterations

    def encrypt(self, plain_text: str) -> str:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        from Crypto.Hash import HMAC, SHA256

        salt = get_random_bytes(SALT_SIZE)
        iv = get_random_bytes(IV_SIZE)
        enc_key, mac_key = _cbc_derive_key_pair(self.password, salt, self.iterations)

        cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)
        padded = pkcs7_pad(plain_text.encode("utf-8"))
        ciphertext = cipher.encrypt(padded)

        h = HMAC.new(mac_key, digestmod=SHA256)
        h.update(iv + ciphertext)
        mac = h.digest()

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

            # 先按"分离密钥"方案验证（新加密格式）；
            # 失败再回退"同密钥"方案（旧 $AC2$ 密文兼容，命中时提示重新加密）
            verified = False
            schemes = (
                _cbc_derive_key_pair(self.password, salt, self.iterations),
                (derive_key(self.password, salt, self.iterations),
                 derive_key(self.password, salt, self.iterations)),
            )
            for idx, (enc_key, mac_key) in enumerate(schemes):
                h = HMAC.new(mac_key, digestmod=SHA256)
                h.update(iv + ciphertext)
                try:
                    h.verify(mac)
                except ValueError:
                    continue
                cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)
                try:
                    raw_padded = cipher.decrypt(ciphertext)
                    raw = pkcs7_unpad(raw_padded)
                except ValueError:
                    raise PasswordError(i18n.t("err_pwd_or_tamper"))
                verified = True
                if idx == 1:
                    # 旧同密钥方案命中：提示用新版本重新加密
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
            # 无前缀旧版（无 HMAC）：遍历兼容探测矩阵
            for iterations, hash_name, dk_len in LEGACY_DECRYPT_PROBES:
                key = derive_key(self.password, salt, iterations, _get_hash_module(hash_name), dk_len)
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                try:
                    raw_padded = cipher.decrypt(ciphertext)
                    raw = pkcs7_unpad(raw_padded)
                except ValueError:
                    continue
                # CBC 无认证：错误候选可能碰巧产生合法 padding，
                # 用可读性过滤误报，乱码则继续探测下一个候选
                if not _is_readable_text(raw):
                    continue
                _note_legacy_params(iterations, hash_name, dk_len)
                return _decode_with_hint(raw)
            raise PasswordError(i18n.t("err_pwd_or_tamper"))


# ====================== 密码生成与强度检测 ======================

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
    if low in weak_list:
        score = 0
        tips.append(i18n.t("tip_weak_common"))

    # 键盘走位序列（连续键位）
    keyboard_seq = {
        "qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx", "qwertyuiop",
        "asdfghjkl", "zxcvbnm", "poiuytrewq", "mnbvcxz", "lkjhgfdsa",
        "qweasd", "asdzxc", "qwerty123", "1q2w3e", "qwe123",
    }
    if low in keyboard_seq:
        score = 0
        tips.append(i18n.t("tip_keyboard"))

    # 纯数字 / 单一重复字符 / 连续递增或递减序列
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

    # "单词+年份"组合（如 Summer2024、Welcome2025）：短密码且以 20xx 结尾
    import re as _re
    if len(pwd) <= 12 and _re.fullmatch(r"[A-Za-z][A-Za-z0-9]{1,7}[12][0-9]{3}", pwd) and score > 0:
        score = max(1, score - 2)
        tips.append(i18n.t("tip_year"))

    if score >= SCORE_STRONG:
        level = i18n.t("strength_strong")
    elif score >= SCORE_MEDIUM:
        level = i18n.t("strength_medium")
    else:
        level = i18n.t("strength_weak")

    return level, tips


# ====================== 自动检测编码 ======================

# 评分竞争候选：UTF-8 严格优先；失败后在其余编码中按可读性择优
ENCODING_PRIORITY = ("utf-8", "gbk", "big5", "shift_jis")
# 最终兜底：Latin-1 将每个字节一一映射为字符，不丢信息、绝不抛异常
FALLBACK_ENCODING = "latin-1"


def _encoding_score(text: str, enc: str) -> int:
    """给一段解码文本打可读性分：普通字符加分，乱码特征扣分。

    关键特征：GBK 字节被 Shift_JIS 误解码时会大量产生"半角假名"
    （U+FF61-U+FF9F），而真正的日文文本以"全角假名"（U+3040-U+30FF）
    为主；据此对与目标编码特征不一致的候选重罚。
    """
    score = 0
    full_kana = 0   # 全角平/片假名
    half_kana = 0   # 半角假名
    latin_ext = 0   # 拉丁扩展字符
    cjk = 0         # CJK 汉字
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

    # 中文双字节编码的文本不应大量混入假名或拉丁扩展
    if enc in ("gbk", "big5"):
        if (full_kana + half_kana + latin_ext) >= total * 0.3:
            score -= total * 10
    # Shift_JIS 编码的文本应以假名为主，且不应以半角假名占绝对主导；
    # 全角假名占比高是日文文本的强信号（GBK 误判时只产生半角假名），额外加分
    elif enc == "shift_jis":
        if (full_kana + half_kana) < total * 0.4:
            score -= total * 5
        if half_kana > full_kana:
            score -= total * 5
        if full_kana >= total * 0.5:
            score += total * 5
    return score


def detect_decode(data: bytes) -> Tuple[str, str]:
    """自动检测字节数据的文本编码并解码。

    返回 (解码后的文本, 检测到的编码名)。
    1) 优先 UTF-8 严格解码——多字节序列模式设计严谨，误判率极低；
    2) 仅当 UTF-8 失败时，才在 GBK / Big5 / Shift_JIS / Latin-1 中
       取"可读性得分"最高的解码结果（宽松双字节编码互有重叠，
       无法做到绝对精确，但可避免明显乱码）；
    3) 全部失败时用 UTF-8 宽松模式兜底，保证不抛异常。
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
    # Latin-1 兜底：逐字节映射，保留原始信息且绝不抛异常
    return data.decode(FALLBACK_ENCODING), FALLBACK_ENCODING


def _decode_with_hint(data: bytes) -> str:
    """解码字节并返回文本；若检测到的编码不是 UTF-8，输出一句提示。"""
    text, enc = detect_decode(data)
    if enc != "utf-8":
        printer.info(i18n.t("auto_encoding", enc=enc))
    return text


# ====================== 编码与哈希 ======================

def b64_encode(plain_text: str) -> str:
    return base64.b64encode(plain_text.encode("utf-8")).decode("utf-8")


def b64_decode(enc_str: str) -> str:
    try:
        data = base64.b64decode(enc_str, validate=True)
    except Exception:
        # 兼容粘贴/旧密文：剥掉首尾空白（换行等）后再次严格解码；
        # 仍失败才退回宽松模式（容忍无害杂音，旧版密文可能存在）
        try:
            data = base64.b64decode(enc_str.strip(), validate=True)
        except Exception:
            data = base64.b64decode(enc_str)
    return _decode_with_hint(data)


def _decode_pack_b64(b64_str: str) -> bytes:
    """密文包 Base64 解码：严格优先；失败后去除空白字符（换行/空格/Tab）
    再严格解码——容忍粘贴换行，但拒绝非空白非法字符（防篡改静默通过）。"""
    try:
        return base64.b64decode(b64_str, validate=True)
    except Exception:
        import re as _re
        cleaned = _re.sub(r"\s+", "", b64_str)
        return base64.b64decode(cleaned, validate=True)


# 哈希算法白名单（calc_hash / calc_file_hash 共用）
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
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
            read_size += len(chunk)
            if file_size > 10 * 1024 * 1024:
                percent = read_size / file_size * 100
                print(f"\rProgress: {percent:.1f}%", end="", flush=True)

    if file_size > 10 * 1024 * 1024:
        print()

    return h.hexdigest()


# ====================== RSA 工具 ======================

def rsa_generate_keys(protect_passphrase: Optional[str] = None,
                      key_bits: int = RSA_KEY_BITS):
    from Crypto.PublicKey import RSA

    key = RSA.generate(key_bits)
    # 强度自检：确保生成的是预期位数的密钥
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


# ====================== 二维码工具 ======================

def generate_qr(text: str, save_path: Optional[str] = None):
    import qrcode

    # 内容长度限制：过长内容可能导致编码失败或 DoS
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


# ====================== 文件加解密 ======================

# 流式处理分块大小（大文件不整体读入内存）
CHUNK_SIZE = 65536
# 大文件进度提示阈值
PROGRESS_THRESHOLD = 10 * 1024 * 1024


def encrypt_file(input_path: str, output_path: str, password: str):
    """v3 流式加密：$CP3$ + Argon2id + AES-256-GCM，tag 写在文件末尾。"""
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    salt = get_random_bytes(ARGON2_SALT_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)
    key = derive_argon2_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

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


def decrypt_file(input_path: str, output_path: str, password: str):
    from Crypto.Cipher import AES

    file_size = os.path.getsize(input_path)

    with open(input_path, "rb") as f_in:
        header = f_in.read(len(PREFIX_AES_V3))

        if header == PREFIX_AES_V3:
            # v3 流式：salt + nonce + 密文 + tag(末尾)
            if file_size < len(PREFIX_AES_V3) + ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE:
                raise CipherCorruptedError(i18n.t("err_len_invalid"))
            salt = f_in.read(ARGON2_SALT_SIZE)
            nonce = f_in.read(NONCE_SIZE)
            key = derive_argon2_key(password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

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
                # 解密失败：清理半成品输出，避免残留损坏文件
                if os.path.exists(output_path):
                    os.remove(output_path)
                raise
            finally:
                if show_progress:
                    print()
            return

        elif header == PREFIX_AES_GCM_V2:
            # v2：salt + nonce + tag + 密文
            salt = f_in.read(SALT_SIZE)
            nonce = f_in.read(NONCE_SIZE)
            tag = f_in.read(TAG_SIZE)
            ciphertext = f_in.read()

            key = derive_key(password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            try:
                plain_data = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                raise PasswordError(i18n.t("err_pwd_or_file_tamper"))

            with open(output_path, "wb") as f_out:
                f_out.write(plain_data)
            return

        raise FormatNotSupportedError(i18n.t("err_file_format"))


def get_decrypt_output_path(input_path: str) -> str:
    """解密输出路径：去掉 .enc 后缀还原原文件名；不以 .enc 结尾则追加 .dec 后缀。"""
    if input_path.lower().endswith(".enc"):
        return input_path[:-4]
    return input_path + ".dec"


def next_available_copy_name(target_path: str) -> str:
    """目标文件已存在时，生成下一个可用的副本名：xxx (1).ext、xxx (2).ext ..."""
    root, ext = os.path.splitext(target_path)
    i = 1
    while True:
        candidate = f"{root} ({i}){ext}"
        if not os.path.exists(candidate):
            return candidate
        i += 1


# ====================== 内容类型识别 ======================

def detect_content_type(text: str) -> Tuple[str, Optional[str], Optional[str]]:
    """识别输入内容的类型。

    返回 (类型词条 key, 编码名或 None, Base64 解码预览或 None)。
    类型：plain / b64 / aes_gcm / aes_cbc / binary。
    """
    stripped = text.strip()

    try:
        data = base64.b64decode(stripped, validate=True)
    except Exception:
        data = None

    if data is not None and data:
        # 前缀匹配后再校验密文结构长度，避免 Base64 偶然解码成前缀字节的误判
        # v3/GCM：前缀 + salt16 + nonce12 + tag16；CBC：前缀 + salt16 + iv16 + mac32 + 至少16字节密文
        gcm_min = len(PREFIX_AES_V3) + ARGON2_SALT_SIZE + NONCE_SIZE + TAG_SIZE
        cbc_min = len(PREFIX_AES_CBC_V2) + SALT_SIZE + IV_SIZE + HMAC_SIZE + 16

        if data.startswith(PREFIX_AES_V3) and len(data) >= gcm_min:
            return "analyze_type_aes_gcm", None, None
        if data.startswith(PREFIX_AES_GCM_V2) and len(data) >= gcm_min:
            return "analyze_type_aes_gcm", None, None
        if data.startswith(PREFIX_AES_CBC_V2) and len(data) >= cbc_min:
            return "analyze_type_aes_cbc", None, None

        dec_text, enc = detect_decode(data)
        score = _encoding_score(dec_text, enc)
        if score >= max(1, len(dec_text) * 0.5):
            return "analyze_type_b64", enc, dec_text

        # 不可读：长度符合旧版 AES 结构（salt16+nonce12+tag16=44，
        # CBC 还需 16 字节 IV 与至少 16 字节密文）则视为疑似旧版密文
        if len(data) >= 44:
            return "analyze_type_aes_legacy", None, None
        return "analyze_type_binary", None, None

    # 非 Base64：判断是否为可读文本
    if stripped and all(
        ord(c) >= 0x20 and ord(c) != 0x7F
        for c in stripped
    ):
        return "analyze_type_plain", "unicode", None
    return "analyze_type_binary", None, None


def analyze_and_show(text: str):
    """输出识别报告，AES 密文时询问是否尝试解密。"""
    ctype, enc, preview = detect_content_type(text)
    printer.info(i18n.t("analyze_title"))
    print(i18n.t(ctype))
    if enc:
        print(i18n.t("analyze_encoding", enc=enc))
    if preview is not None:
        printer.info(i18n.t("auto_b64_detected"))
        print(preview)
    if ctype in ("analyze_type_aes_gcm", "analyze_type_aes_cbc", "analyze_type_aes_legacy"):
        if input(i18n.t("analyze_try_decrypt")).strip().lower() == "y":
            _try_all_aes_decrypt(text)


# ====================== 自动解密 ======================

def auto_decrypt_text(enc_str: str):
    try:
        res = b64_decode(enc_str)
        printer.ok(i18n.t("auto_b64_detected"))
        print(res)

        force = input(i18n.t("auto_force_aes")).strip().lower()
        if force == "y":
            _try_all_aes_decrypt(enc_str)
        return
    except (base64.binascii.Error, UnicodeDecodeError):
        pass

    printer.info(i18n.t("auto_try_aes"))
    _try_all_aes_decrypt(enc_str)


def _try_all_aes_decrypt(enc_str: str):
    pwd = getpass.getpass(i18n.t("decrypt_pwd"))

    try:
        tool = AESGCMTool(pwd)
        res = tool.decrypt(enc_str)
        printer.ok(i18n.t("auto_gcm_ok"))
        print(res)
        return
    except (PasswordError, CipherCorruptedError):
        pass

    try:
        tool = AESCBCWithHMACTool(pwd)
        res = tool.decrypt(enc_str)
        printer.ok(i18n.t("auto_cbc_ok"))
        print(res)
        return
    except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
        printer.fail(str(e))
    except Exception as e:
        _handle_unexpected_error(e)


# ====================== 密码输入（带二次确认） ======================

def _handle_unexpected_error(e: Exception) -> None:
    """未知异常处理：打印完整回溯避免静默掩盖程序错误，再给出简短提示。"""
    import traceback
    traceback.print_exception(type(e), e, e.__traceback__)
    printer.fail(str(e))


def get_password_with_confirm(prompt_key: str = "encrypt_pwd") -> str:
    """输入密码并二次确认；不一致时提示并重新输入（加密路径防输错）。"""
    while True:
        pwd = getpass.getpass(i18n.t(prompt_key))
        if len(pwd) > PASSWORD_MAX_LEN:
            printer.fail(i18n.t("pwd_too_long", max=PASSWORD_MAX_LEN))
            continue
        confirm = getpass.getpass(i18n.t("confirm_pwd"))
        if pwd == confirm:
            return pwd
        printer.warn(i18n.t("pwd_mismatch"))


# ====================== 剪贴板封装 ======================

def copy_to_clipboard(text: str):
    try:
        import pyperclip
        pyperclip.copy(text)
        printer.ok(i18n.t("copy_done"))
    except Exception:
        printer.warn(i18n.t("copy_fail"))


# ====================== 菜单 ======================

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
    print("0. 退出" if i18n.lang == "zh" else "0. Exit")


def menu_loop():
    interrupt_count = 0  # 连续 Ctrl+C 计数（连续两次退出）
    while True:
        show_menu()
        choice = input(i18n.t("input_choice")).strip()
        interrupt_count = 0  # 正常输入后重置中断计数

        try:
            if choice == "1":
                pwd = get_password_with_confirm("encrypt_pwd")
                content = input(i18n.t("input_plain"))
                tool = AESGCMTool(pwd)
                result = tool.encrypt(content)
                printer.ok(i18n.t("success"))
                print(result)
                copy_to_clipboard(result)

            elif choice == "2":
                enc_str = input(i18n.t("input_cipher"))
                pwd = getpass.getpass(i18n.t("decrypt_pwd"))
                tool = AESGCMTool(pwd)
                try:
                    res = tool.decrypt(enc_str)
                    printer.ok(i18n.t("success"))
                    print(res)
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "3":
                pwd = get_password_with_confirm("encrypt_pwd")
                content = input(i18n.t("input_plain"))
                tool = AESCBCWithHMACTool(pwd)
                result = tool.encrypt(content)
                printer.ok(i18n.t("success"))
                print(result)
                copy_to_clipboard(result)

            elif choice == "4":
                enc_str = input(i18n.t("input_cipher"))
                pwd = getpass.getpass(i18n.t("decrypt_pwd"))
                tool = AESCBCWithHMACTool(pwd)
                try:
                    res = tool.decrypt(enc_str)
                    printer.ok(i18n.t("success"))
                    print(res)
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "5":
                text = input(i18n.t("input_cipher"))
                analyze_and_show(text)

            elif choice == "6":
                content = input(i18n.t("input_plain"))
                printer.ok(i18n.t("success"))
                print(b64_encode(content))

            elif choice == "7":
                b64_text = input(i18n.t("input_cipher"))
                try:
                    plain = b64_decode(b64_text)
                    printer.ok(i18n.t("success"))
                    print(plain)
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "8":
                content = input(i18n.t("input_plain"))
                alg = input(i18n.t("alg_prompt")).strip().lower() or "sha256"
                try:
                    result = calc_hash(content.encode("utf-8"), alg)
                    printer.ok(i18n.t("success"))
                    print(result)
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "9":
                file_path = normalize_path(input(i18n.t("file_path")))
                if not os.path.isfile(file_path):
                    printer.fail(i18n.t("file_not_exist"))
                    continue
                alg = input(i18n.t("alg_prompt")).strip().lower() or "sha256"
                try:
                    result = calc_file_hash(file_path, alg)
                    printer.ok(i18n.t("success"))
                    print(result)
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "10":
                len_str = input(i18n.t("len_prompt")).strip()
                pwd_len = int(len_str) if len_str.isdigit() and int(len_str) >= 8 else 16
                pwd = generate_random_password(pwd_len)
                printer.ok(i18n.t("success"))
                print(pwd)
                copy_to_clipboard(pwd)

            elif choice == "11":
                pwd = input(i18n.t("pwd_input_prompt"))
                level, tips = check_password_strength(pwd)
                printer.info(i18n.t("strength_label", level=level))
                for tip in tips:
                    printer.warn(tip)

            elif choice == "12":
                printer.info(i18n.t("rsa_gen_keys"))
                bits_str = input(i18n.t("rsa_bits_prompt")).strip()
                bits = int(bits_str) if bits_str.isdigit() else RSA_KEY_BITS
                if bits not in (2048, 3072, 4096):
                    printer.fail(i18n.t("rsa_bits_invalid"))
                    continue
                use_pass = input(i18n.t("rsa_protect_prompt")).strip().lower()
                passphrase = None
                if use_pass == "y":
                    passphrase = get_password_with_confirm("rsa_enter_passphrase")
                priv, pub = rsa_generate_keys(passphrase, key_bits=bits)
                priv_path = os.path.join(SCRIPT_DIR, "rsa_private.pem")
                pub_path = os.path.join(SCRIPT_DIR, "rsa_public.pem")
                with open(priv_path, "wb") as f:
                    f.write(priv)
                with open(pub_path, "wb") as f:
                    f.write(pub)
                printer.ok(i18n.t("success"))
                print(i18n.t("rsa_private_label", path=priv_path))
                print(i18n.t("rsa_public_label", path=pub_path))

            elif choice == "13":
                pub_path = normalize_path(input(i18n.t("rsa_pub_path_prompt")))
                text = input(i18n.t("rsa_enter_text"))
                try:
                    result = rsa_encrypt(pub_path, text)
                    printer.ok(i18n.t("success"))
                    print(result)
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "14":
                pri_path = normalize_path(input(i18n.t("rsa_pri_path_prompt")))
                b64_text = input(i18n.t("rsa_enter_cipher"))
                passphrase = None
                if input(i18n.t("rsa_has_passphrase")).strip().lower() == "y":
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
                input_path = normalize_path(input(i18n.t("file_path")))
                if not os.path.isfile(input_path):
                    printer.fail(i18n.t("file_not_exist"))
                    continue
                pwd = get_password_with_confirm("encrypt_pwd")
                output_path = input_path + ".enc"
                encrypt_file(input_path, output_path, pwd)
                printer.ok(i18n.t("file_encrypted_to", path=output_path))

            elif choice == "16":
                input_path = normalize_path(input(i18n.t("file_path")))
                if not os.path.isfile(input_path):
                    printer.fail(i18n.t("file_not_exist"))
                    continue
                pwd = getpass.getpass(i18n.t("decrypt_pwd"))
                output_path = get_decrypt_output_path(input_path)
                if os.path.exists(output_path):
                    confirm = input(i18n.t("target_exists")).strip().lower()
                    if confirm != "y":
                        output_path = next_available_copy_name(output_path)
                        printer.warn(i18n.t("kept_original") + f" {output_path}")
                try:
                    decrypt_file(input_path, output_path, pwd)
                    printer.ok(i18n.t("file_decrypted_to", path=output_path))
                except (CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    printer.fail(str(e))
                except Exception as e:
                    _handle_unexpected_error(e)

            elif choice == "17":
                if not (importlib.util.find_spec("qrcode") and importlib.util.find_spec("PIL")):
                    printer.fail(i18n.t("qr_missing_pkg"))
                    continue
                text = input(i18n.t("qr_content_prompt"))
                save = input(i18n.t("qr_save_prompt")).strip().lower()
                save_path = None
                if save == "y":
                    save_path = input(i18n.t("qr_filename_prompt")).strip()
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
                img_path = normalize_path(input(i18n.t("file_path")))
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
                text = input(i18n.t("analyze_input"))
                analyze_and_show(text)

            elif choice == "0":
                confirm = input(i18n.t("exit_confirm")).strip().lower()
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
            # 其他异常打印完整回溯，避免掩盖程序内部错误
            import traceback
            traceback.print_exc()
            printer.fail(str(e))


# ====================== 命令行模式 ======================

def cli_mode():
    # 预解析 --lang，使帮助文本也跟随所选语言
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", choices=["zh", "en"], default="zh")
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
    parser.add_argument("--lang", choices=["zh", "en"], default="zh", help=i18n.t("cli_lang_help"))
    parser.add_argument("--version", action="version", version="2.7.2")

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

    # CLI 模式同样检查核心依赖
    missing_core, _ = check_dependencies()
    if missing_core:
        printer.fail(i18n.t("core_deps_missing"))
        printer.info(i18n.t("missing_list") + ", ".join(missing_core))
        printer.info(i18n.t("install_cmd_global") + " pip install " + " ".join(missing_core))
        sys.exit(1)

    if args.encrypt or args.decrypt:
        if args.password_file:
            # 从文件读取密码（避免密码暴露于进程列表）
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
            # 使用 -p 传入密码时，提醒进程列表暴露风险（不阻断，兼容脚本调用）
            printer.warn(i18n.t("cli_p_warn"))
        elif args.encrypt:
            # CLI 加密且未用 -p 指定密码：交互输入并二次确认
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
                    tool = AESGCMTool(pwd)
                    print(tool.encrypt(target))
                else:
                    tool = AESGCMTool(pwd)
                    print(tool.decrypt(target))
        except Exception as e:
            printer.fail(str(e))
        return


# ====================== 启动流程 ======================

def select_language():
    print("1. 中文")
    print("2. English")
    choice = input("请选择语言 / Select language: ").strip()
    if choice == "2":
        return "en"
    return "zh"


def main():
    global i18n, printer

    # 有命令行参数时直接进入 CLI 模式（用 --lang 或默认中文），不做交互询问
    if len(sys.argv) > 1:
        cli_mode()
        return

    lang = select_language()
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
