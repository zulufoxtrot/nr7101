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

from nr7101.util import parse_traffic_object

logger = logging.getLogger(__name__)


class NR7101Exception(Exception):
    def __init__(self, error):
        self.error = error


class NR7101:
    def __init__(self, url, username, password, params={}):
        self.url = url
        self.params = params
        password_b64 = base64.b64encode(password.encode("utf-8")).decode("utf-8")
        
        # NR7101 is using by default self-signed certificates, so ignore the warnings
        self.params["verify"] = False
        urllib3.disable_warnings()
                
        self.rsa_key = None
        # Request to GET /GetRSAPublickKey if it doesn't return 200, then false
        with requests.get(
            self.url + "/getRSAPublickKey", None, **self.params
        ) as r:
            self.rsa_key = r.json().get("RSAPublicKey", None)
            if self.rsa_key == "None":  # yes, the router can return a "None" str
                self.rsa_key = None
            self.encryption_required = bool(self.rsa_key)
            self.aes_key = os.urandom(32)  # 256-bit AES key
            self.iv = os.urandom(16)  # 256-bit IV (some routers use 16 bytes; match what router expects)
            if self.encryption_required:
                logger.debug("Encryption enabled for router")
        
        self.login_params = {
            "Input_Account": username,
            "Input_Passwd": password_b64,
            "currLang": "en",
            "RememberPassword": 0,
            "SHA512_password": False,
        }
        self.session_key = None

    def login(self):
        logger.log("Logging in...")
        if self.encryption_required:
           login_json = self.encrypt_request(self.login_params)
        else:
            login_json = json.dumps(self.login_params)

        with requests.post(
            self.url + "/UserLogin", data=login_json, **self.params
        ) as r:
            if r.status_code != 200:
                logger.error("Unauthorized")
                return None

            # Update cookies
            self.params["cookies"] = requests.utils.dict_from_cookiejar(r.cookies)
            data = r.json()
            if "iv" in data:
                self.session_key = self.decrypt_response(data)["sessionkey"]
            else:
                self.session_key = data["sessionkey"]
            return self.session_key

    def logout(self):
        with requests.get(
            f"{self.url}/cgi-bin/UserLogout?sessionkey={self.session_key}", **self.params
        ) as r:
            assert r.status_code == 200

    def get_json_object(self, oid):
        with requests.get(self.url + "/cgi-bin/DAL?oid=" + oid, **self.params) as r:
            r.raise_for_status()
            data = r.json()
            if "iv" in data:
                data = self.decrypt_response(r.json())

            if not data["Object"]:
                return None
            return data["Object"][0]
        
    def do_request(self, path):
        with requests.get(
            self.url + path, **self.params
        ) as r:
            r.raise_for_status()
            data = r.json()
            if "iv" in data:
                data = self.decrypt_response(r.json())
            
            assert data["result"] == "ZCFG_SUCCESS"
            return data

    def reboot(self):
        if self.session_key is None:
            self.login()

        logger.info("Rebooting...")
        with requests.post(
            f"{self.url}/cgi-bin/Reboot?sessionkey={self.session_key}", **self.params
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
        decrypted_data = unpad(decrypted_padded, 16)

        # Return as JSON (dict)
        return json.loads(decrypted_data.decode("utf-8"))
