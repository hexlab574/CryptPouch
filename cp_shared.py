# -*- coding: utf-8 -*-
"""CryptPouch shared foundation: i18n, UI printer, config system, errors,
dependency checks and the module-wide constants/state.

Other modules import this one and access mutable state dynamically
(cp_shared.CONFIG / cp_shared.DEFAULT_ITERATIONS ...) so that
set_config(reload=True) and language switches propagate correctly."""

import importlib
import json
import os
import sys
import time
from typing import Optional, List, Tuple, Dict, Any, Union

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
    for key in ("allow_legacy_decrypt", "reject_symlinks"):
        if not isinstance(cfg[key], bool):
            cfg[key] = DEFAULT_CONFIG[key]
    for key in ("audit_log", "artifact_dir"):
        if not isinstance(cfg[key], str) or "\x00" in cfg[key]:
            cfg[key] = DEFAULT_CONFIG[key]
    return cfg


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
        elif key == "max_file_size":
            # bytes; 0 means "no limit", negatives are rejected
            try:
                ivalue = int(value)
            except (TypeError, ValueError):
                raise ValueError(i18n.t("cfg_invalid_value", k=key, v=value))
            if ivalue < 0:
                raise ValueError(i18n.t("cfg_invalid_value", k=key, v=value))
            out[key] = ivalue
            continue
        elif key in ("allow_legacy_decrypt", "reject_symlinks"):
            if not isinstance(value, bool):
                raise ValueError(i18n.t("cfg_invalid_value", k=key, v=value))
        elif key in ("audit_log", "artifact_dir"):
            if not isinstance(value, str) or "\x00" in value:
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


def get_artifact_dir() -> str:
    """Directory for RSA keys and QR images: the configured artifact_dir when set,
    otherwise the script directory (the historical behavior)."""
    configured = (CONFIG.get("artifact_dir") or "").strip()
    if configured:
        return os.path.abspath(os.path.expanduser(configured))
    return SCRIPT_DIR


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


class CryptoToolError(Exception):
    pass


class CipherCorruptedError(CryptoToolError):
    pass


class PasswordError(CryptoToolError):
    pass


class FormatNotSupportedError(CryptoToolError):
    pass


# ====================== Module constants & state ======================
LANG = {
    "zh": {
        "welcome": "你好呀～欢迎使用 AES256 加密工具箱 ",
        "usage_tip": "这个工具可以帮你做文本加密、文件加密、哈希、RSA 和二维码。",
        "legal_tip": "注意：仅供学习研究与个人本地使用，不要用于非法用途",
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
        "pwd_empty": "密码不能为空",
        "cli_conflict_actions": "不能同时使用 -e 和 -d，请只保留一个",
        "cli_target_required": "-f 需要与 -e 或 -d 一起使用，否则没有要处理的目标",
        "cli_hash_failed": "哈希计算失败",
        "file_too_large": "文件大小超过配置上限（{size} 字节），已跳过。",
        "ask_elevate": "安装依赖需要管理员权限。是否以管理员身份重试？(y/N): ",
        "elevate_note": "将弹出 UAC 提权窗口，请确认。",
        "elevate_cancel": "已取消管理员提权。",
        "elevate_fail": "管理员提权安装失败：{err}",
        "elevate_ok": "依赖已以管理员权限安装。",
        "elevate_continue": "安装完成后请按回车键继续，程序将自动重启。",
        "install_denied": "安装失败：权限不足。可尝试以管理员权限重试。",
        "symlink_rejected": "出于安全考虑，已拒绝符号链接路径：{path}",
        "legacy_decrypt_disabled": "已禁用 legacy（v2/无前缀 CBC）解密路径。如需解密旧密文，请设置 allow_legacy_decrypt=true。",
        "format_legacy_upgrade": "该密文使用旧版格式（密文头未被认证），建议用 reencrypt 升级到 $CP4$ / $CC2$ / $AC3$。",
        "decrypt_pwd": "请输入解密密码：",
        "input_plain": "请输入明文：",
        "input_cipher": "请输入密文：",
        "file_path": "请输入文件路径：",
        "file_not_exist": "文件不存在",
        "success": "完成啦 ",
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
        "batch_keep_source_hint": "提示：加密结果写成 .enc 副本，原文件保留；确认无误后再自行删除原文件。",
        "batch_summary": "结果：成功 {ok} 个，失败 {failed} 个，跳过 {skipped} 个。",
        "batch_existing_kept": "其中 {n} 个已有同名密文，已保留未覆盖（如需重新加密请加 --overwrite 或先删掉旧密文）。",
        "batch_overwritten_n": "其中 {n} 个覆盖了已存在的同名明文。",
        "encrypt_exists_skip": "已存在同名密文，已保留未覆盖：",
        "cli_overwrite_help": "覆盖已存在的 .enc 密文（默认保留旧密文）",
        "overwrite_confirm": "已存在同名密文，是否覆盖？(y/N)：",
        "batch_existing_n": "检测到 {n} 个文件已有同名密文。",
        "same_path_rejected": "输入和输出是同一个文件，已拒绝：这样会销毁原始数据。请指定不同的输出路径。",
        "batch_dir_detected": "检测到目录，已切换为批量模式。",
    },
    "en": {
        "welcome": "Hi there! Welcome to the AES256 Crypto Toolkit ",
        "usage_tip": "It supports text encryption, file encryption, hashing, RSA, and QR codes.",
        "legal_tip": "Note: For learning and personal local use only. Do not use for illegal purposes.",
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
        "pwd_empty": "Password must not be empty.",
        "cli_conflict_actions": "Cannot use -e and -d at the same time; keep only one",
        "cli_target_required": "-f needs -e or -d; without one there is no target to process",
        "cli_hash_failed": "Hash calculation failed",
        "file_too_large": "File size exceeds the configured limit ({size} bytes); skipped.",
        "ask_elevate": "Installing dependencies needs administrator rights. Retry as administrator? (y/N): ",
        "elevate_note": "A UAC elevation prompt will appear - please confirm it.",
        "elevate_cancel": "Elevation cancelled.",
        "elevate_fail": "Elevated install failed: {err}",
        "elevate_ok": "Dependencies installed with administrator rights.",
        "elevate_continue": "Press Enter after the installation finishes; the app will restart.",
        "install_denied": "Install failed: permission denied. Try again as administrator.",
        "symlink_rejected": "Refusing a symbolic link path for security reasons: {path}",
        "legacy_decrypt_disabled": "Legacy (v2 / prefixless CBC) decryption is disabled. Set allow_legacy_decrypt=true to decrypt old ciphertext.",
        "format_legacy_upgrade": "This ciphertext uses an older format (authenticated header missing). Re-encrypt it to $CP4$ / $CC2$ / $AC3$ with reencrypt.",
        "decrypt_pwd": "Enter decryption password:",
        "input_plain": "Enter plaintext:",
        "input_cipher": "Enter ciphertext:",
        "file_path": "Enter file path:",
        "file_not_exist": "File does not exist.",
        "success": "Done ",
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
        "batch_keep_source_hint": "Note: encryption writes .enc copies and keeps the original files; delete them yourself once verified.",
        "batch_summary": "Result: {ok} succeeded, {failed} failed, {skipped} skipped.",
        "batch_existing_kept": "{n} of them already had a .enc file, which was kept (use --overwrite or delete the old ciphertext to re-encrypt).",
        "batch_overwritten_n": "{n} of them overwrote an existing file with the same name.",
        "encrypt_exists_skip": "A ciphertext with that name already exists, kept as is:",
        "cli_overwrite_help": "Overwrite existing .enc ciphertext (default keeps the old one)",
        "overwrite_confirm": "That ciphertext already exists. Overwrite it? (y/N): ",
        "batch_existing_n": "{n} files already have a ciphertext with the same name.",
        "same_path_rejected": "Input and output are the same file; refused because it would destroy the original data. Use a different output path.",
        "batch_dir_detected": "Directory detected; switched to batch mode.",
    }
}


_ANSI = {"yellow": "\x1b[33m", "red": "\x1b[31m", "reset": "\x1b[0m"}


_VT_INITIALIZED = False


i18n = I18n()


printer = Printer(i18n)


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
    "max_file_size": 0,                # file size cap in bytes for file ops; 0 = no limit
    "allow_legacy_decrypt": True,      # permit v2 / prefixless legacy decryption paths
    "reject_symlinks": True,           # refuse symlinked inputs/outputs for file operations
    "audit_log": "",                   # optional JSONL audit log path (empty = disabled)
    "artifact_dir": "",                # RSA key / QR image output dir (empty = script dir)
}


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
    "max_file_size":      ("CRYPTPOUCH_MAX_FILE_SIZE", "int"),
    "allow_legacy_decrypt": ("CRYPTPOUCH_ALLOW_LEGACY_DECRYPT", "bool"),
    "reject_symlinks":    ("CRYPTPOUCH_REJECT_SYMLINKS", "bool"),
    "audit_log":          ("CRYPTPOUCH_AUDIT_LOG", "str"),
    "artifact_dir":       ("CRYPTPOUCH_ARTIFACT_DIR", "str"),
}


CONFIG = load_config()


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


DEFAULT_ITERATIONS = CONFIG["iterations"]


LEGACY_ITERATIONS = 100_000


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


RSA_KEY_BITS = CONFIG["rsa_bits"]


PASSWORD_MAX_LEN = CONFIG["password_max_len"]


SCORE_STRONG = CONFIG["score_strong"]


SCORE_MEDIUM = CONFIG["score_medium"]


QR_MAX_LEN = CONFIG["qr_max_len"]


KEYBOARD_PATTERN_MIN_LEN = CONFIG["keyboard_pattern_min_len"]


PREFIX_AES_GCM_V2 = b"$AG2$"


PREFIX_AES_CBC_V2 = b"$AC2$"


PREFIX_AES_V3 = b"$CP3$"


PREFIX_CHACHA20 = b"$CC1$"


# Authenticated-header formats (v2.11.0): the prefix + salt + nonce (iv) are fed
# to the AEAD as associated data, so any header tampering or algorithm-downgrade
# swap fails authentication instead of merely yielding garbage plaintext.
PREFIX_AES_V4 = b"$CP4$"


PREFIX_CHACHA20_V2 = b"$CC2$"


PREFIX_AES_CBC_V3 = b"$AC3$"


ARGON2_TIME_COST = CONFIG["argon2_time_cost"]


ARGON2_MEMORY_COST_KIB = CONFIG["argon2_memory_kib"]   # 64 MiB


ARGON2_PARALLELISM = CONFIG["argon2_parallelism"]


# The progress line is re-drawn at most this often (seconds). Printing once per
# block made a 1 GB file emit ~16k console writes, which dominated the runtime
# on Windows terminals.
PROGRESS_MIN_INTERVAL = 0.15


ARGON2_SALT_SIZE = 16


ARGON2_HASH_LEN = 32             # AES-256


WEAK_PASSWORD_MAX_BYTES = 32 * 1024 * 1024


_WEAK_DICT_CACHE = {"path": None, "words": None}


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


ENCODING_PRIORITY = ("utf-8", "gbk", "big5", "shift_jis")


FALLBACK_ENCODING = "latin-1"


HASH_ALGORITHMS = ("md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b")


# 1 MiB blocks: large enough to keep the Python loop and syscall overhead low
# on multi-GB files, small enough to stay memory friendly on weak devices.
CHUNK_SIZE = 1024 * 1024


PROGRESS_THRESHOLD = 10 * 1024 * 1024


CIPHER_MODES = ("gcm", "cbc", "chacha20")


MAX_PASSWORD_ATTEMPTS = 5



# Apply console encoding setup once at import time (as in the original single file).
_setup_console_encoding()
