#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import json
import base64
import os
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA

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

        # Step 1: Call GetInfoNoLogin to establish session
        info_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-GB,en;q=0.5',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0'
        }

        info_params = self.params.copy()
        info_params['headers'] = info_headers

        with requests.get(self.url + "/GetInfoNoLogin", **info_params) as info_r:
            if info_r.cookies:
                self.params["cookies"] = requests.utils.dict_from_cookiejar(info_r.cookies)

        # Step 2: Get RSA public key
        rsa_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-GB,en;q=0.5',
            'X-Requested-With': 'XMLHttpRequest',
            'If-Modified-Since': 'Thu, 01 Jun 1970 00:00:00 GMT',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0'
        }

        rsa_params = self.params.copy()
        if 'headers' in rsa_params:
            rsa_params['headers'].update(rsa_headers)
        else:
            rsa_params['headers'] = rsa_headers

        with requests.get(self.url + "/getRSAPublickKey", **rsa_params) as r:
            # Update session cookies from the RSA key request (if any)
            if r.cookies:
                if "cookies" not in self.params:
                    self.params["cookies"] = {}
                new_cookies = requests.utils.dict_from_cookiejar(r.cookies)
                self.params["cookies"].update(new_cookies)

            if r.status_code == 200:
                try:
                    response_json = r.json()
                    self.rsa_key = response_json.get("RSAPublicKey", None)
                    if self.rsa_key == "None":     # router can return a "None" str
                        self.rsa_key = None
                except Exception:
                    self.rsa_key = None
            else:
                self.rsa_key = None

            self.encryption_required = bool(self.rsa_key)
            self.aes_key = os.urandom(32)  # 256-bit AES key
            self.iv = os.urandom(32)       # 32-byte IV to match browser behavior

        # Login parameters
        self.login_params = {
            "Input_Account": username,
            "Input_Passwd": password_b64,
            "currLang": "en",
            "RememberPassword": 0,
        }
        self.sessionkey = None

    def load_cookies(self, cookiefile):
        cookies = {}
        try:
            with open(cookiefile, "rt") as f:
                cookies = json.load(f)
            self.params["cookies"] = cookies
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def clear_cookies(self):
        self.params.pop("cookies", None)

    def store_cookies(self, cookiefile):
        try:
            cookies = self.params["cookies"]
            with open(cookiefile, "wt") as f:
                json.dump(cookies, f)
        except KeyError:
            pass

    def login(self):
        if self.encryption_required:
           login_json = self.encrypt_request(self.login_params)
        else:
            login_json = json.dumps(self.login_params)

        login_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'If-Modified-Since': 'Thu, 01 Jun 1970 00:00:00 GMT',
            'X-Requested-With': 'XMLHttpRequest',
            'Origin': self.url,
            'DNT': '1',
            'Sec-GPC': '1',
            'Connection': 'keep-alive',
            'Referer': f'{self.url}/login',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0'
        }

        login_params = self.params.copy()
        if 'headers' in login_params:
            login_params['headers'].update(login_headers)
        else:
            login_params['headers'] = login_headers

        with requests.post(
            self.url + "/UserLogin", data=login_json.encode('utf-8'), **login_params
        ) as r:
            if r.status_code != 200:
                return False

            # Update cookies with any new ones from login response
            if r.cookies:
                new_cookies = requests.utils.dict_from_cookiejar(r.cookies)
                if "cookies" not in self.params:
                    self.params["cookies"] = {}
                self.params["cookies"].update(new_cookies)

            if self.encryption_required:
                response_data = self.decrypt_response(r.json())
            else:
                response_data = r.json()
            self.sessionkey = response_data["sessionkey"]
            return True

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
            if obj and "ipIface" in obj and "ipIfaceSt" in obj:
                for iface, iface_st in zip(obj["ipIface"], obj["ipIfaceSt"]):
                    ret[iface["X_ZYXEL_IfName"]] = iface_st
            return ret

        # Define endpoint priorities based on router type
        endpoints_to_try = [
            ("cellwan_status", "cellular"),
            ("Traffic_Status", "traffic"),
            ("cardpage_status", "cardpage"),
            ("lan", "lan"),
            ("lanhosts", "lanhosts"),
            ("wifi_easy_mesh", "wifi_mesh"),
            ("one_connect", "one_connect"),
            ("status", "device"),
        ]

        while retries > 0:
            try:
                result = {}
                successful_endpoints = 0

                for endpoint, key in endpoints_to_try:
                    try:
                        if endpoint == "Traffic_Status":
                            # Special handling for traffic data
                            traffic_obj = self.get_json_object(endpoint)
                            data = parse_traffic_object(traffic_obj)
                        else:
                            data = self.get_json_object(endpoint)

                        if data:
                            result[key] = data
                            successful_endpoints += 1
                    except requests.exceptions.HTTPError as e:
                        if e.response.status_code == 401:
                            # Re-raise 401 to trigger login retry
                            raise
                    except Exception:
                        continue

                if successful_endpoints > 0:
                    return result

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    # Unauthorized - attempt login
                    login_success = self.login()
                    if not login_success:
                        break
                elif e.response.status_code == 500:
                    # Internal server error - retry without cookies
                    self.clear_cookies()
                retries -= 1
        return None

    def probe_available_endpoints(self):
        """Probe which endpoints are available on this router for debugging."""
        endpoints_to_probe = [
            "cellwan_status",
            "Traffic_Status",
            "cardpage_status",
            "lan",
            "lanhosts",
            "wifi_easy_mesh",
            "one_connect",
            "status",
            "paren_ctl",
            "wlan_status",
            "eth_status"
        ]

        available_endpoints = []
        for endpoint in endpoints_to_probe:
            try:
                data = self.get_json_object(endpoint)
                if data:
                    available_endpoints.append(endpoint)
            except Exception:
                continue

        return available_endpoints

    def get_json_object(self, oid):
        # Add session key to URL for authenticated requests
        if self.sessionkey:
            url = self.url + "/cgi-bin/DAL?oid=" + oid + "&sessionkey=" + str(self.sessionkey)
        else:
            url = self.url + "/cgi-bin/DAL?oid=" + oid

        with requests.get(url, **self.params) as r:
            r.raise_for_status()

            if self.encryption_required:
                j = self.decrypt_response(r.json())
            else:
                j = r.json()

            if j.get("result") != "ZCFG_SUCCESS" or not j.get("Object"):
                return None

            return j["Object"][0]

    def reboot(self):
        if self.sessionkey is None:
            self.login()

        with requests.post(
            f"{self.url}/cgi-bin/Reboot?sessionkey={self.sessionkey}", **self.params
        ) as r:
            r.raise_for_status()
            j = r.json()
            assert j["result"] == "ZCFG_SUCCESS"

    def encrypt_request(self, json_data: dict) -> str:
        # Use compact JSON formatting to match browser behavior
        json_body = json.dumps(json_data, separators=(',', ':')).encode('utf-8')
        padded = pad(json_body, 16)

        # Encrypt the login parameters using AES (use only first 16 bytes of IV for CBC)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv[:16])
        ciphertext = cipher.encrypt(padded)
        content_b64 = base64.b64encode(ciphertext).decode()

        if not self.rsa_key:
            raise Exception("No RSA key available for encryption")

        try:
            rsa_key = RSA.import_key(self.rsa_key.encode('utf-8'))
            cipher_rsa = PKCS1_v1_5.new(rsa_key)

            # Encrypt the base64-encoded AES key
            base64_encoded_key = base64.b64encode(self.aes_key)
            encrypted_key = cipher_rsa.encrypt(base64_encoded_key)
            key_b64 = base64.b64encode(encrypted_key).decode()

            iv_b64 = base64.b64encode(self.iv).decode()

            return json.dumps({
                "content": content_b64,
                "key": key_b64,
                "iv": iv_b64
            })

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def decrypt_response(self, encrypted_json: dict) -> dict:
        # Decode base64 values
        response_iv = base64.b64decode(encrypted_json["iv"])
        ciphertext = base64.b64decode(encrypted_json["content"])

        # Use the response IV for decryption (first 16 bytes for AES-CBC)
        iv_for_decrypt = response_iv[:16]

        # Decrypt with AES (CBC mode) using the same key as request encryption
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv_for_decrypt)
        decrypted_padded = cipher.decrypt(ciphertext)

        # Try standard unpadding first
        try:
            decrypted_data = unpad(decrypted_padded, 16)
        except ValueError:
            # Fallback for routers that don't use proper PKCS7 padding
            try:
                # Remove trailing null bytes
                decrypted_data = decrypted_padded.rstrip(b'\x00')
                if len(decrypted_data) == len(decrypted_padded) and len(decrypted_padded) > 0:
                    # Try manual PKCS7 unpadding
                    padding_length = decrypted_padded[-1]
                    if 0 < padding_length <= 16:
                        decrypted_data = decrypted_padded[:-padding_length]
                    else:
                        decrypted_data = decrypted_padded
            except Exception:
                # Last resort: use raw decrypted data
                decrypted_data = decrypted_padded

        # Decode and parse as JSON
        try:
            json_string = decrypted_data.decode("utf-8")
            return json.loads(json_string)
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            logger.error(f"Error processing JSON response: {e}")
            raise Exception(f"Failed to process decrypted response: {e}")
