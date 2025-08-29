#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import json
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

import requests
import urllib3

logger = logging.getLogger(__name__)


class NR7101Exception(Exception):
    def __init__(self, error):
        self.error = error


class NR7101:
    def __init__(self, url, username, password, params={}):
        self.url = url
        self.params = params
        self.rsa_key = None
        self.encryption_required = False
        password_b64 = base64.b64encode(password.encode("utf-8")).decode("utf-8")

        # NR7101 is using by default self-signed certificates, so ignore the warnings
        self.params["verify"] = False
        urllib3.disable_warnings()

        logger.debug("WAWA")

        # Request to GET /GetRSAPublickKey if it doesn't return 200, then false
        with requests.get(
            self.url + "/getRSAPublickKey", None, **self.params
        ) as r:
            self.rsa_key = r.json().get("RSAPublicKey", None)
            if self.rsa_key == "None":     # yes, the router can return a "None" str
                self.rsa_key = None
            self.encryption_required = bool(self.rsa_key)
            self.aes_key = os.urandom(32)  # 256-bit AES key
            self.iv = os.urandom(16)       # 256-bit IV (some routers use 16 bytes; match what router expects)
            if self.encryption_required:
                logger.debug("Encryption enabled for router")

        self.login_params = {
            "Input_Account": username,
            "Input_Passwd": password_b64,
            "currLang": "en",
            "RememberPassword": 0,
            "SHA512_password": False,
        }
        self.sessionkey = None

    def load_cookies(self, cookiefile):
        cookies = {}
        try:
            with open(cookiefile, "rt") as f:
                cookies = json.load(f)
            logger.debug("Cookies loaded")
            self.params["cookies"] = cookies
        except FileNotFoundError:
            logger.debug("Cookie file does not exist, ignoring.")
        except json.JSONDecodeError:
            logger.warn("Ignoring invalid cookie file.")

    def clear_cookies(self):
        self.params.pop("cookies", None)

    def store_cookies(self, cookiefile):
        try:
            cookies = self.params["cookies"]
        except KeyError:
            logger.warn("No cookie to write")
            return

        with open(cookiefile, "wt") as f:
            json.dump(cookies, f)
        logger.debug("Cookies saved")

    def login(self):
        print("Logging in...")
        if self.encryption_required:
           login_json = self.encrypt_request(self.login_params)
        else:
            login_json = json.dumps(self.login_params)


        with requests.post(
            self.url + "/UserLogin", data=login_json, **self.params
        ) as r:
            if r.status_code != 200:
                logger.error("Unauthorized")
                return

            # Update cookies
            self.params["cookies"] = requests.utils.dict_from_cookiejar(r.cookies)
            if self.encryption_required:
                self.sessionkey = self. decrypt_response(r.json())["sessionkey"]
            else:
                self.sessionkey = r.json()["sessionkey"]

    def logout(self, sessionkey=None):
        if sessionkey is None:
            sessionkey = self.sessionkey
        with requests.get(
            f"{self.url}/cgi-bin/UserLogout?sessionkey={sessionkey}", **self.params
        ) as r:
            assert r.status_code == 200

    def connect(self):
        with requests.get(self.url + "/getBasicInformation", **self.params) as r:
            assert r.status_code == 200
            assert r.json()["result"] == "ZCFG_SUCCESS", "Connection failure"

        # Check login
        with requests.get(self.url + "/UserLoginCheck", **self.params) as r:
            assert r.status_code == 200

    def get_status(self, retries=2):
        def parse_traffic_object(obj):
            ret = {}
            for iface, iface_st in zip(obj["ipIface"], obj["ipIfaceSt"]):
                ret[iface["X_ZYXEL_IfName"]] = iface_st
            return ret

        while retries > 0:
            try:
                cellular = self.get_json_object("cellwan_status")
                traffic = parse_traffic_object(self.get_json_object("Traffic_Status"))
                return {
                    "cellular": cellular,
                    "traffic": traffic,
                }
            except requests.exceptions.HTTPError as e:
                logger.warn(e)
                if e.response.status_code == 401:
                    # Unauthorized
                    logger.info("Login")
                    self.login()
                elif e.response.status_code == 500:
                    logger.info(
                        "Internal server error received. Retrying without cookies."
                    )
                    self.clear_cookies()
                retries -= 1
        return None

    def get_json_object(self, oid):
        with requests.get(self.url + "/cgi-bin/DAL?oid=" + oid, **self.params) as r:
            r.raise_for_status()
            if self.encryption_required:
                j = self.decrypt_response(r.json())
            else:
                j = r.json()
            assert j["result"] == "ZCFG_SUCCESS"
            if not j["Object"]:
                return None
            return j["Object"][0]

    def reboot(self):
        if self.sessionkey is None:
            self.login()

        logger.info("Rebooting...")
        with requests.post(
            f"{self.url}/cgi-bin/Reboot?sessionkey={self.sessionkey}", **self.params
        ) as r:
            r.raise_for_status()
            j = r.json()
            assert j["result"] == "ZCFG_SUCCESS"

    def encrypt_request(self, json_data: dict) -> str:
        json_body = json.dumps(json_data).encode('utf-8')
        padded = pad(json_body, 16)
        # Encrypt the login parameters using AES
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        ciphertext = cipher.encrypt(padded)
        content_b64 = base64.b64encode(ciphertext).decode()

        rsa_key = RSA.import_key(self.rsa_key.encode('utf-8'))
        cipher_rsa = PKCS1_v1_5.new(rsa_key)
        aes_key_b64 = base64.b64encode(self.aes_key).decode()
        encrypted_key = cipher_rsa.encrypt(aes_key_b64.encode())
        key_b64 = base64.b64encode(encrypted_key).decode()

        return json.dumps({
            "content": content_b64,
            "key": key_b64,
            "iv": base64.b64encode(self.iv).decode()
        })

    def decrypt_response(self, encrypted_json: dict) -> dict:
        # Decode base64 values
        iv = base64.b64decode(encrypted_json["iv"])[:16]  # Ensure IV is 16 bytes
        ciphertext = base64.b64decode(encrypted_json["content"])

        # Decrypt with AES (CBC mode)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)

        # Try standard unpadding first
        try:
            decrypted_data = unpad(decrypted_padded, 16)
        except ValueError as e:
            logger.debug(f"Standard unpadding failed: {e}")
            # Some routers (like EX5601-T0) may not use proper PKCS7 padding
            # Try removing null bytes or manual padding removal
            try:
                # Remove trailing null bytes
                decrypted_data = decrypted_padded.rstrip(b'\x00')
                # If that doesn't work, try manual PKCS7 padding removal
                if not decrypted_data or decrypted_data[-1] > 16:
                    decrypted_data = decrypted_padded
                else:
                    # Manual PKCS7 unpadding
                    padding_length = decrypted_padded[-1]
                    if padding_length <= 16:
                        decrypted_data = decrypted_padded[:-padding_length]
                    else:
                        decrypted_data = decrypted_padded
            except Exception as manual_error:
                logger.debug(f"Manual unpadding also failed: {manual_error}")
                # Last resort: use raw decrypted data
                decrypted_data = decrypted_padded

        # Return as JSON (dict)
        return json.loads(decrypted_data.decode("utf-8"))
