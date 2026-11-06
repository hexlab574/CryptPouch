# -*- coding: utf-8 -*-
"""CryptPouch v2.11.2 - AES256 encryption toolbox (interactive menu + CLI).
Version: 2.11.2
License: MIT
Note: For learning, research and personal local use only.

Modularized: this file is the CLI entry point; the implementation lives in
cp_shared / cp_crypto / cp_utils / cp_files / cp_admin. All public symbols are
re-exported here so existing imports (cryptpouch_api, tests) keep working."""
import argparse
import getpass
import importlib.util
import os
import sys
import time
from typing import List
import cp_shared
import cp_crypto
import cp_utils
import cp_files
import cp_admin

# Re-export every public symbol so `import CryptPouch as cp` keeps working.
from cp_shared import *
from cp_crypto import *
from cp_utils import *
from cp_files import *
from cp_admin import *
from cp_shared import _setup_console_encoding, _ANSI, _VT_INITIALIZED, _CONFIG_ENV_MAP, _validate_config_values, _refresh_derived_constants, _ensure_vt, _color_enabled, _KEYBOARD_LAYOUT, _WEAK_DICT_CACHE
from cp_crypto import _wipe_memory, _get_hash_module, _cbc_derive_key_pair, _note_legacy_params, _is_readable_text, _load_weak_password_dict, _keyboard_run_len
from cp_utils import _encoding_score, _decode_with_hint, _decode_pack_b64, _safe_input, _validate_password_len, _restrict_permissions, _text_decrypt_with_retry, _handle_unexpected_error
from cp_files import _encrypt_text_with_mode, _collect_targets, _peek_pack_prefix, _try_text_decrypt_family, _try_all_aes_decrypt, _fsync_dir, _reject_symlink, _audit, _check_open_size

def show_menu():
    cp_shared.printer.info(cp_shared.i18n.t("menu_title"))
    print("1. AES-GCM 加密" if cp_shared.i18n.lang == "zh" else "1. AES-GCM Encrypt")
    print("2. AES-GCM 解密" if cp_shared.i18n.lang == "zh" else "2. AES-GCM Decrypt")
    print("3. AES-CBC 加密" if cp_shared.i18n.lang == "zh" else "3. AES-CBC Encrypt")
    print("4. AES-CBC 解密" if cp_shared.i18n.lang == "zh" else "4. AES-CBC Decrypt")
    print("5. 自动识别解密" if cp_shared.i18n.lang == "zh" else "5. Auto Decrypt")
    print("6. Base64 编码" if cp_shared.i18n.lang == "zh" else "6. Base64 Encode")
    print("7. Base64 解码" if cp_shared.i18n.lang == "zh" else "7. Base64 Decode")
    print("8. 文本哈希" if cp_shared.i18n.lang == "zh" else "8. Text Hash")
    print("9. 文件哈希" if cp_shared.i18n.lang == "zh" else "9. File Hash")
    print("10. 随机密码生成" if cp_shared.i18n.lang == "zh" else "10. Random Password")
    print("11. 密码强度检测" if cp_shared.i18n.lang == "zh" else "11. Password Strength")
    print("12. RSA 生成密钥对" if cp_shared.i18n.lang == "zh" else "12. RSA Generate Keys")
    print("13. RSA 加密" if cp_shared.i18n.lang == "zh" else "13. RSA Encrypt")
    print("14. RSA 解密" if cp_shared.i18n.lang == "zh" else "14. RSA Decrypt")
    print("15. 文件加密" if cp_shared.i18n.lang == "zh" else "15. File Encrypt")
    print("16. 文件解密" if cp_shared.i18n.lang == "zh" else "16. File Decrypt")

    if importlib.util.find_spec("qrcode") and importlib.util.find_spec("PIL"):
        print("17. 生成二维码" if cp_shared.i18n.lang == "zh" else "17. Generate QR Code")
    else:
        print("17. 生成二维码（需安装 qrcode pillow）" if cp_shared.i18n.lang == "zh" else "17. Generate QR Code (needs qrcode pillow)")

    if importlib.util.find_spec("pyzbar") and importlib.util.find_spec("PIL"):
        print("18. 解析二维码" if cp_shared.i18n.lang == "zh" else "18. Decode QR Code")
    else:
        print("18. 解析二维码（需安装 pyzbar pillow）" if cp_shared.i18n.lang == "zh" else "18. Decode QR Code (needs pyzbar pillow)")

    print("19. 自动识别内容类型" if cp_shared.i18n.lang == "zh" else "19. Analyze Content Type")
    print("20. ChaCha20-Poly1305 加密" if cp_shared.i18n.lang == "zh" else "20. ChaCha20-Poly1305 Encrypt")
    print("21. ChaCha20-Poly1305 解密" if cp_shared.i18n.lang == "zh" else "21. ChaCha20-Poly1305 Decrypt")
    print("22. 密钥轮转（文本）" if cp_shared.i18n.lang == "zh" else "22. Re-encrypt Text")
    print("23. 密钥轮转（文件）" if cp_shared.i18n.lang == "zh" else "23. Re-encrypt File")
    print("24. 批量加密（目录/文件）" if cp_shared.i18n.lang == "zh" else "24. Batch Encrypt (dir/file)")
    print("25. 批量解密（目录/文件）" if cp_shared.i18n.lang == "zh" else "25. Batch Decrypt (dir/file)")
    print("0. 退出" if cp_shared.i18n.lang == "zh" else "0. Exit")


def _ask_overwrite(path, action="encrypt"):
    """Ask once before a batch encrypt that would replace existing ciphertext.

    Returns True only when the user explicitly says yes; every other outcome
    keeps the old files untouched."""
    if action != "encrypt":
        return False
    try:
        files, _ = cp_files._collect_targets(path, None, True, for_encrypt=True)
    except Exception:
        return False
    n = sum(1 for f in files if os.path.exists(f + ".enc"))
    if not n:
        return False
    cp_shared.printer.warn(cp_shared.i18n.t("batch_existing_n", n=n))
    return cp_utils._safe_input(cp_shared.i18n.t("overwrite_confirm")).strip().lower() == "y"


def menu_loop():
    interrupt_count = 0  # consecutive Ctrl+C counter (exit on two consecutive presses)
    while True:
        show_menu()
        choice = cp_utils._safe_input(cp_shared.i18n.t("input_choice")).strip()
        interrupt_count = 0  # reset the interrupt counter after a normal input

        try:
            if choice == "1":
                pwd = cp_utils.get_password_with_confirm("encrypt_pwd")
                content = cp_utils._safe_input(cp_shared.i18n.t("input_plain"))
                tool = cp_crypto.AESGCMTool(pwd)
                result = tool.encrypt(content)
                cp_shared.printer.ok(cp_shared.i18n.t("success"))
                print(result)
                cp_utils.copy_to_clipboard(result)

            elif choice == "2":
                enc_str = cp_utils._safe_input(cp_shared.i18n.t("input_cipher"))
                cp_utils._text_decrypt_with_retry(lambda pwd: cp_crypto.AESGCMTool(pwd).decrypt(enc_str))

            elif choice == "3":
                pwd = cp_utils.get_password_with_confirm("encrypt_pwd")
                content = cp_utils._safe_input(cp_shared.i18n.t("input_plain"))
                tool = cp_crypto.AESCBCWithHMACTool(pwd)
                result = tool.encrypt(content)
                cp_shared.printer.ok(cp_shared.i18n.t("success"))
                print(result)
                cp_utils.copy_to_clipboard(result)

            elif choice == "4":
                enc_str = cp_utils._safe_input(cp_shared.i18n.t("input_cipher"))
                cp_utils._text_decrypt_with_retry(lambda pwd: cp_crypto.AESCBCWithHMACTool(pwd).decrypt(enc_str))

            elif choice == "5":
                text = cp_utils._safe_input(cp_shared.i18n.t("input_cipher"))
                cp_files.analyze_and_show(text)

            elif choice == "6":
                content = cp_utils._safe_input(cp_shared.i18n.t("input_plain"))
                cp_shared.printer.ok(cp_shared.i18n.t("success"))
                print(cp_utils.b64_encode(content))

            elif choice == "7":
                b64_text = cp_utils._safe_input(cp_shared.i18n.t("input_cipher"))
                try:
                    plain = cp_utils.b64_decode(b64_text)
                    cp_shared.printer.ok(cp_shared.i18n.t("success"))
                    print(plain)
                except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    cp_shared.printer.fail(str(e))
                except Exception as e:
                    cp_utils._handle_unexpected_error(e)

            elif choice == "8":
                content = cp_utils._safe_input(cp_shared.i18n.t("input_plain"))
                alg = cp_utils._safe_input(cp_shared.i18n.t("alg_prompt")).strip().lower() or "sha256"
                try:
                    result = cp_utils.calc_hash(content.encode("utf-8"), alg)
                    cp_shared.printer.ok(cp_shared.i18n.t("success"))
                    print(result)
                except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    cp_shared.printer.fail(str(e))
                except Exception as e:
                    cp_utils._handle_unexpected_error(e)

            elif choice == "9":
                file_path = cp_crypto.normalize_path(cp_utils._safe_input(cp_shared.i18n.t("file_path")))
                if not os.path.isfile(file_path):
                    cp_shared.printer.fail(cp_shared.i18n.t("file_not_exist"))
                    continue
                alg = cp_utils._safe_input(cp_shared.i18n.t("alg_prompt")).strip().lower() or "sha256"
                try:
                    result = cp_utils.calc_file_hash(file_path, alg)
                    cp_shared.printer.ok(cp_shared.i18n.t("success"))
                    print(result)
                except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    cp_shared.printer.fail(str(e))
                except Exception as e:
                    cp_utils._handle_unexpected_error(e)

            elif choice == "10":
                len_str = cp_utils._safe_input(cp_shared.i18n.t("len_prompt")).strip()
                pwd_len = int(len_str) if len_str.isdigit() and int(len_str) >= 8 else 16
                pwd = cp_crypto.generate_random_password(pwd_len)
                cp_shared.printer.ok(cp_shared.i18n.t("success"))
                print(pwd)
                cp_utils.copy_to_clipboard(pwd)

            elif choice == "11":
                pwd = cp_utils._safe_input(cp_shared.i18n.t("pwd_input_prompt"))
                level, tips = cp_crypto.check_password_strength(pwd)
                cp_shared.printer.info(cp_shared.i18n.t("strength_label", level=level))
                for tip in tips:
                    cp_shared.printer.warn(tip)

            elif choice == "12":
                cp_shared.printer.info(cp_shared.i18n.t("rsa_gen_keys"))
                bits_str = cp_utils._safe_input(cp_shared.i18n.t("rsa_bits_prompt")).strip()
                bits = int(bits_str) if bits_str.isdigit() else cp_shared.RSA_KEY_BITS
                if bits not in (2048, 3072, 4096):
                    cp_shared.printer.fail(cp_shared.i18n.t("rsa_bits_invalid"))
                    continue
                use_pass = cp_utils._safe_input(cp_shared.i18n.t("rsa_protect_prompt")).strip().lower()
                passphrase = None
                if use_pass == "y":
                    passphrase = cp_utils.get_password_with_confirm("rsa_enter_passphrase")
                priv, pub = cp_utils.rsa_generate_keys(passphrase, key_bits=bits)
                priv_path = os.path.join(cp_shared.get_artifact_dir(), "rsa_private.pem")
                pub_path = os.path.join(cp_shared.get_artifact_dir(), "rsa_public.pem")
                with open(priv_path, "wb") as f:
                    f.write(priv)
                cp_utils._restrict_permissions(priv_path)
                with open(pub_path, "wb") as f:
                    f.write(pub)
                cp_shared.printer.ok(cp_shared.i18n.t("success"))
                print(cp_shared.i18n.t("rsa_private_label", path=priv_path))
                print(cp_shared.i18n.t("rsa_public_label", path=pub_path))

            elif choice == "13":
                pub_path = cp_crypto.normalize_path(cp_utils._safe_input(cp_shared.i18n.t("rsa_pub_path_prompt")))
                text = cp_utils._safe_input(cp_shared.i18n.t("rsa_enter_text"))
                try:
                    result = cp_utils.rsa_encrypt(pub_path, text)
                    cp_shared.printer.ok(cp_shared.i18n.t("success"))
                    print(result)
                except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    cp_shared.printer.fail(str(e))
                except Exception as e:
                    cp_utils._handle_unexpected_error(e)

            elif choice == "14":
                pri_path = cp_crypto.normalize_path(cp_utils._safe_input(cp_shared.i18n.t("rsa_pri_path_prompt")))
                b64_text = cp_utils._safe_input(cp_shared.i18n.t("rsa_enter_cipher"))
                passphrase = None
                if cp_utils._safe_input(cp_shared.i18n.t("rsa_has_passphrase")).strip().lower() == "y":
                    passphrase = getpass.getpass(cp_shared.i18n.t("rsa_enter_passphrase"))
                try:
                    result = cp_utils.rsa_decrypt(pri_path, b64_text, passphrase)
                    cp_shared.printer.ok(cp_shared.i18n.t("success"))
                    print(result)
                except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    cp_shared.printer.fail(str(e))
                except Exception as e:
                    cp_utils._handle_unexpected_error(e)

            elif choice == "15":
                input_path = cp_crypto.normalize_path(cp_utils._safe_input(cp_shared.i18n.t("file_path")))
                if os.path.isdir(input_path):
                    # Accept a folder here too: no need to remember menu 24.
                    cp_shared.printer.warn(cp_shared.i18n.t("batch_dir_detected"))
                    pwd = cp_utils.get_password_with_confirm("encrypt_pwd")
                    try:
                        result = cp_files.batch_encrypt(input_path, pwd, overwrite=_ask_overwrite(input_path, "encrypt"))
                        cp_shared.printer.ok(cp_shared.i18n.t("batch_encrypted_n", n=len(result["encrypted"])))
                        print(cp_shared.i18n.t("batch_summary", ok=len(result["encrypted"]),
                                               failed=len(result["failed"]),
                                               skipped=len(result.get("skipped", []))))
                        if result.get("existing"):
                            print(cp_shared.i18n.t("batch_existing_kept", n=len(result["existing"])))
                        if result["encrypted"]:
                            cp_shared.printer.warn(cp_shared.i18n.t("batch_keep_source_hint"))
                        for path, err in result["failed"]:
                            cp_shared.printer.fail(f"{path}: {err}")
                    except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                        cp_shared.printer.fail(str(e))
                    except Exception as e:
                        cp_utils._handle_unexpected_error(e)
                    continue
                if not os.path.isfile(input_path):
                    cp_shared.printer.fail(cp_shared.i18n.t("file_not_exist"))
                    continue
                pwd = cp_utils.get_password_with_confirm("encrypt_pwd")
                output_path = input_path + ".enc"
                if os.path.exists(output_path):
                    # Re-encrypting in place kept the same name, so the folder looked
                    # untouched even though the old ciphertext had been replaced.
                    ans = cp_utils._safe_input(cp_shared.i18n.t("overwrite_confirm")).strip().lower()
                    if ans != "y":
                        cp_shared.printer.warn(cp_shared.i18n.t("encrypt_exists_skip") + " " + output_path)
                        continue
                try:
                    cp_files.encrypt_file(input_path, output_path, pwd)
                    cp_shared.printer.ok(cp_shared.i18n.t("file_encrypted_to", path=output_path))
                except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    cp_shared.printer.fail(str(e))
                except Exception as e:
                    cp_utils._handle_unexpected_error(e)

            elif choice == "16":
                input_path = cp_crypto.normalize_path(cp_utils._safe_input(cp_shared.i18n.t("file_path")))
                if os.path.isdir(input_path):
                    cp_shared.printer.warn(cp_shared.i18n.t("batch_dir_detected"))
                    pwd = getpass.getpass(cp_shared.i18n.t("decrypt_pwd"))
                    try:
                        result = cp_files.batch_decrypt(input_path, pwd)
                        cp_shared.printer.ok(cp_shared.i18n.t("batch_decrypted_n", n=len(result["decrypted"])))
                        print(cp_shared.i18n.t("batch_summary", ok=len(result["decrypted"]),
                                               failed=len(result["failed"]),
                                               skipped=len(result.get("skipped", []))))
                        for path, err in result["failed"]:
                            cp_shared.printer.fail(f"{path}: {err}")
                    except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                        cp_shared.printer.fail(str(e))
                    except Exception as e:
                        cp_utils._handle_unexpected_error(e)
                    continue
                if not os.path.isfile(input_path):
                    cp_shared.printer.fail(cp_shared.i18n.t("file_not_exist"))
                    continue
                output_path = cp_files.get_decrypt_output_path(input_path)
                if os.path.exists(output_path):
                    confirm = cp_utils._safe_input(cp_shared.i18n.t("target_exists")).strip().lower()
                    if confirm != "y":
                        output_path = cp_files.next_available_copy_name(output_path)
                        cp_shared.printer.warn(cp_shared.i18n.t("kept_original") + f" {output_path}")
                for i in range(cp_shared.MAX_PASSWORD_ATTEMPTS):
                    pwd = getpass.getpass(cp_shared.i18n.t("decrypt_pwd"))
                    try:
                        cp_files.decrypt_file(input_path, output_path, pwd)
                    except (cp_shared.PasswordError, cp_shared.CipherCorruptedError) as e:
                        cp_shared.printer.fail(str(e))
                        if i < cp_shared.MAX_PASSWORD_ATTEMPTS - 1:
                            cp_shared.printer.warn(cp_shared.i18n.t("attempts_left", left=cp_shared.MAX_PASSWORD_ATTEMPTS - i - 1))
                        continue
                    except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                        cp_shared.printer.fail(str(e))
                        break
                    except Exception as e:
                        cp_utils._handle_unexpected_error(e)
                        break
                    cp_shared.printer.ok(cp_shared.i18n.t("file_decrypted_to", path=output_path))
                    break
                else:
                    cp_shared.printer.fail(cp_shared.i18n.t("attempts_exceeded"))

            elif choice == "17":
                if not (importlib.util.find_spec("qrcode") and importlib.util.find_spec("PIL")):
                    cp_shared.printer.fail(cp_shared.i18n.t("qr_missing_pkg"))
                    continue
                text = cp_utils._safe_input(cp_shared.i18n.t("qr_content_prompt"))
                save = cp_utils._safe_input(cp_shared.i18n.t("qr_save_prompt")).strip().lower()
                save_path = None
                if save == "y":
                    save_path = cp_utils._safe_input(cp_shared.i18n.t("qr_filename_prompt")).strip()
                    if save_path and not os.path.isabs(save_path):
                        save_path = os.path.join(cp_shared.get_artifact_dir(), save_path)
                try:
                    cp_utils.generate_qr(text, save_path)
                except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    cp_shared.printer.fail(str(e))
                except Exception as e:
                    cp_utils._handle_unexpected_error(e)

            elif choice == "18":
                if not (importlib.util.find_spec("pyzbar") and importlib.util.find_spec("PIL")):
                    cp_shared.printer.fail(cp_shared.i18n.t("zb_missing_pkg"))
                    continue
                img_path = cp_crypto.normalize_path(cp_utils._safe_input(cp_shared.i18n.t("file_path")))
                if not os.path.isfile(img_path):
                    cp_shared.printer.fail(cp_shared.i18n.t("file_not_exist"))
                    continue
                try:
                    results = cp_utils.decode_qr(img_path)
                    if results:
                        cp_shared.printer.ok(cp_shared.i18n.t("success"))
                        for item in results:
                            print(item)
                    else:
                        cp_shared.printer.fail(cp_shared.i18n.t("qr_no_content"))
                except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    cp_shared.printer.fail(str(e))
                except Exception as e:
                    cp_utils._handle_unexpected_error(e)

            elif choice == "19":
                text = cp_utils._safe_input(cp_shared.i18n.t("analyze_input"))
                cp_files.analyze_and_show(text)

            elif choice == "20":
                pwd = cp_utils.get_password_with_confirm("encrypt_pwd")
                content = cp_utils._safe_input(cp_shared.i18n.t("input_plain"))
                tool = cp_crypto.ChaCha20Poly1305Tool(pwd)
                result = tool.encrypt(content)
                cp_shared.printer.ok(cp_shared.i18n.t("success"))
                print(result)
                cp_utils.copy_to_clipboard(result)

            elif choice == "21":
                enc_str = cp_utils._safe_input(cp_shared.i18n.t("input_cipher"))
                cp_utils._text_decrypt_with_retry(lambda pwd: cp_crypto.ChaCha20Poly1305Tool(pwd).decrypt(enc_str))

            elif choice == "22":
                enc_str = cp_utils._safe_input(cp_shared.i18n.t("input_cipher"))
                old_pwd = getpass.getpass(cp_shared.i18n.t("reencrypt_old_pwd"))
                new_pwd = cp_utils.get_password_with_confirm("reencrypt_new_pwd")
                mode = cp_utils._safe_input(cp_shared.i18n.t("reencrypt_mode_prompt")).strip().lower() or "gcm"
                if mode not in cp_shared.CIPHER_MODES:
                    cp_shared.printer.fail(cp_shared.i18n.t("err_cipher_mode"))
                    continue
                try:
                    result = cp_files.reencrypt_text(enc_str, old_pwd, new_pwd, mode)
                    cp_shared.printer.ok(cp_shared.i18n.t("reencrypt_done"))
                    print(result)
                    cp_utils.copy_to_clipboard(result)
                except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    cp_shared.printer.fail(str(e))
                except Exception as e:
                    cp_utils._handle_unexpected_error(e)

            elif choice == "23":
                input_path = cp_crypto.normalize_path(cp_utils._safe_input(cp_shared.i18n.t("file_path")))
                if not os.path.isfile(input_path):
                    cp_shared.printer.fail(cp_shared.i18n.t("file_not_exist"))
                    continue
                old_pwd = getpass.getpass(cp_shared.i18n.t("reencrypt_old_pwd"))
                new_pwd = cp_utils.get_password_with_confirm("reencrypt_new_pwd")
                try:
                    out = cp_files.reencrypt_file(input_path, old_pwd, new_pwd)
                    cp_shared.printer.ok(cp_shared.i18n.t("reencrypt_done"))
                    print(cp_shared.i18n.t("reencrypt_output", path=out))
                except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    cp_shared.printer.fail(str(e))
                except Exception as e:
                    cp_utils._handle_unexpected_error(e)

            elif choice == "24":
                target = cp_crypto.normalize_path(cp_utils._safe_input(cp_shared.i18n.t("batch_path_prompt")))
                pattern = cp_utils._safe_input(cp_shared.i18n.t("batch_pattern_prompt")).strip()
                pwd = cp_utils.get_password_with_confirm("encrypt_pwd")
                try:
                    result = cp_files.batch_encrypt(target, pwd, pattern or None,
                                                    overwrite=_ask_overwrite(target, "encrypt"))
                    cp_shared.printer.ok(cp_shared.i18n.t("batch_encrypted_n", n=len(result["encrypted"])))
                    print(cp_shared.i18n.t("batch_summary", ok=len(result["encrypted"]),
                                           failed=len(result["failed"]),
                                           skipped=len(result.get("skipped", []))))
                    if result.get("existing"):
                        print(cp_shared.i18n.t("batch_existing_kept", n=len(result["existing"])))
                    if result["encrypted"]:
                        cp_shared.printer.warn(cp_shared.i18n.t("batch_keep_source_hint"))
                    for path, err in result["failed"]:
                        cp_shared.printer.fail(f"{path}: {err}")
                except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    cp_shared.printer.fail(str(e))
                except Exception as e:
                    cp_utils._handle_unexpected_error(e)

            elif choice == "25":
                cp_shared.printer.warn(cp_shared.i18n.t("batch_overwrite_hint"))
                target = cp_crypto.normalize_path(cp_utils._safe_input(cp_shared.i18n.t("batch_path_prompt")))
                pattern = cp_utils._safe_input(cp_shared.i18n.t("batch_pattern_prompt")).strip()
                pwd = getpass.getpass(cp_shared.i18n.t("decrypt_pwd"))
                try:
                    result = cp_files.batch_decrypt(target, pwd, pattern or None)
                    cp_shared.printer.ok(cp_shared.i18n.t("batch_decrypted_n", n=len(result["decrypted"])))
                    print(cp_shared.i18n.t("batch_summary", ok=len(result["decrypted"]),
                                           failed=len(result["failed"]),
                                           skipped=len(result.get("skipped", []))))
                    for path, err in result["failed"]:
                        cp_shared.printer.fail(f"{path}: {err}")
                except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
                    cp_shared.printer.fail(str(e))
                except Exception as e:
                    cp_utils._handle_unexpected_error(e)

            elif choice == "0":
                confirm = cp_utils._safe_input(cp_shared.i18n.t("exit_confirm")).strip().lower()
                if confirm == "y":
                    cp_shared.printer.info(cp_shared.i18n.t("bye"))
                    break

            else:
                cp_shared.printer.warn(cp_shared.i18n.t("invalid_choice"))

        except KeyboardInterrupt:
            print()
            if interrupt_count > 0:
                cp_shared.printer.info(cp_shared.i18n.t("bye"))
                sys.exit(0)
            interrupt_count = 1
            cp_shared.printer.warn(cp_shared.i18n.t("ctrl_c_hint"))
        except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
            cp_shared.printer.fail(str(e))
        except MemoryError:
            cp_shared.printer.fail(cp_shared.i18n.t("mem_error"))
            raise
        except Exception as e:
            cp_utils._handle_unexpected_error(e)


def cli_mode():
    # Pre-parse --lang so the help text follows the selected language
    # (default comes from the user config / CRYPTPOUCH_LANG when set)
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", choices=["zh", "en"], default=cp_shared.CONFIG.get("lang") or "zh")
    ns, _ = pre.parse_known_args()

    global i18n, printer
    i18n = cp_shared.I18n(ns.lang)
    printer = cp_shared.Printer(i18n)

    parser = argparse.ArgumentParser(description=i18n.t("cli_desc"))
    parser.add_argument("-e", "--encrypt", help=i18n.t("cli_e_help"))
    parser.add_argument("-d", "--decrypt", help=i18n.t("cli_d_help"))
    parser.add_argument("-p", "--password", help=i18n.t("cli_p_help"))
    parser.add_argument("--password-file", help=i18n.t("cli_password_file_help"))
    parser.add_argument("-f", "--file", action="store_true", help=i18n.t("cli_f_help"))
    parser.add_argument("-o", "--output", help=i18n.t("cli_o_help"))
    parser.add_argument("--overwrite", action="store_true", help=i18n.t("cli_overwrite_help"))
    parser.add_argument("--hash", help=i18n.t("cli_hash_help"))
    parser.add_argument("--cipher", choices=list(cp_shared.CIPHER_MODES), default="gcm", help=i18n.t("cli_cipher_help"))
    parser.add_argument("--lang", choices=["zh", "en"], default=cp_shared.CONFIG.get("lang") or "zh", help=i18n.t("cli_lang_help"))
    parser.add_argument("--version", action="version", version="2.11.2")

    args = parser.parse_args()

    if args.hash:
        target = args.encrypt or args.decrypt
        if not target or not os.path.isfile(target):
            printer.fail(i18n.t("file_not_exist"))
            sys.exit(1)
        try:
            h = cp_utils.calc_file_hash(target, args.hash)
            print(h)
        except Exception as e:
            printer.fail(str(e))
        return

    # CLI mode also checks core dependencies
    missing_core, _ = cp_shared.check_dependencies()
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
                if len(pwd) > cp_shared.PASSWORD_MAX_LEN:
                    printer.fail(i18n.t("pwd_too_long", max=cp_shared.PASSWORD_MAX_LEN))
                    sys.exit(1)
            except Exception as e:
                printer.fail(str(e))
                sys.exit(1)
        elif args.password:
            if len(args.password) > cp_shared.PASSWORD_MAX_LEN:
                printer.fail(i18n.t("pwd_too_long", max=cp_shared.PASSWORD_MAX_LEN))
                sys.exit(1)
            pwd = args.password
            # Warn about process-list exposure when -p is used (non-blocking for script compatibility)
            printer.warn(i18n.t("cli_p_warn"))
        elif args.encrypt:
            # CLI encryption without -p: prompt interactively and confirm the password
            pwd = cp_utils.get_password_with_confirm("encrypt_pwd")
        else:
            pwd = getpass.getpass(i18n.t("decrypt_pwd"))
            if len(pwd) > cp_shared.PASSWORD_MAX_LEN:
                printer.fail(i18n.t("pwd_too_long", max=cp_shared.PASSWORD_MAX_LEN))
                sys.exit(1)
        target = args.encrypt or args.decrypt

        try:
            norm_target = cp_crypto.normalize_path(target)
            if args.file and os.path.isdir(norm_target):
                # A folder passed with -f used to be rejected outright, which made
                # whole file classes look unsupported. Process the tree instead.
                if args.encrypt:
                    res = cp_files.batch_encrypt(norm_target, pwd, overwrite=args.overwrite)
                    printer.ok(i18n.t("batch_encrypted_n", n=len(res["encrypted"])))
                    print(i18n.t("batch_summary", ok=len(res["encrypted"]),
                                 failed=len(res["failed"]),
                                 skipped=len(res.get("skipped", []))))
                    if res.get("existing"):
                        print(i18n.t("batch_existing_kept", n=len(res["existing"])))
                    if res["encrypted"]:
                        printer.warn(i18n.t("batch_keep_source_hint"))
                    for path, err in res["failed"]:
                        printer.fail(f"{path}: {err}")
                    sys.exit(1 if res["failed"] else 0)
                else:
                    res = cp_files.batch_decrypt(norm_target, pwd)
                    printer.ok(i18n.t("batch_decrypted_n", n=len(res["decrypted"])))
                    print(i18n.t("batch_summary", ok=len(res["decrypted"]),
                                 failed=len(res["failed"]),
                                 skipped=len(res.get("skipped", []))))
                    for path, err in res["failed"]:
                        printer.fail(f"{path}: {err}")
                    sys.exit(1 if res["failed"] else 0)
            if args.file:
                if args.encrypt:
                    out = args.output or target + ".enc"
                    if (not args.output and not args.overwrite and os.path.exists(out)):
                        # Re-encrypting over the old ciphertext kept the same file
                        # name, so the folder looked unchanged after a real run.
                        printer.warn(i18n.t("encrypt_exists_skip") + " " + out)
                    else:
                        cp_files.encrypt_file(target, out, pwd)
                        printer.ok(i18n.t("cli_file_encrypted"))
                else:
                    if args.output:
                        out = args.output
                    else:
                        out = cp_files.get_decrypt_output_path(target)
                        if os.path.exists(out):
                            # Never overwrite silently: pick the next free
                            # "name (1).txt" and say so. Failing here made a
                            # perfectly good .enc file look undecryptable.
                            out = cp_files.next_available_copy_name(out)
                            printer.warn(i18n.t("kept_original") + " " + out)
                    cp_files.decrypt_file(target, out, pwd)
                    printer.ok(i18n.t("cli_file_decrypted", path=out))
            else:
                if args.encrypt:
                    print(cp_files._encrypt_text_with_mode(target, pwd, args.cipher))
                else:
                    print(cp_files.try_text_decrypt(target, pwd))
        except Exception as e:
            # A non-zero status is what scripts and CI actually read; printing
            # the error and returning 0 made failures look like successes.
            printer.fail(str(e))
            sys.exit(1)
        return


def select_language():
    print("1. 中文")
    print("2. English")
    choice = cp_utils._safe_input("请选择语言 / Select language: ").strip()
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
    lang = cp_shared.CONFIG.get("lang") or select_language()
    i18n = cp_shared.I18n(lang)
    printer = cp_shared.Printer(i18n)

    printer.info(i18n.t("welcome"))
    printer.info(i18n.t("usage_tip"))
    printer.warn(i18n.t("legal_tip"))

    missing_core, missing_optional = cp_shared.check_dependencies()

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
    except EOFError:
        # Input stream ended (piped / non-interactive): exit cleanly instead of
        # crashing with a traceback.
        print()
        printer.info(i18n.t("bye"))
        sys.exit(0)



if __name__ == "__main__":
    main()
