#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import json
import base64
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5

import requests
import urllib3

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Let the parent logger handle console output to avoid duplicate logs


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

        # Step 1: Call GetInfoNoLogin to establish session (like browser does)
        logger.debug("Calling GetInfoNoLogin to establish session...")
        info_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-GB,en;q=0.5',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0'
        }

        info_params = self.params.copy()
        info_params['headers'] = info_headers

        with requests.get(self.url + "/GetInfoNoLogin", **info_params) as info_r:
            logger.debug(f"GetInfoNoLogin status: {info_r.status_code}")
            logger.debug(f"GetInfoNoLogin response: {info_r.text}")
            if info_r.cookies:
                self.params["cookies"] = requests.utils.dict_from_cookiejar(info_r.cookies)
                logger.debug(f"Session cookies from GetInfoNoLogin: {self.params['cookies']}")

        # Step 2: Get RSA public key (now with session established)
        logger.debug("Attempting to get RSA public key...")

        # Add headers that match what the browser sends
        rsa_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-GB,en;q=0.5',
            'X-Requested-With': 'XMLHttpRequest',
            'If-Modified-Since': 'Thu, 01 Jun 1970 00:00:00 GMT',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0'
        }

        # Merge with existing params (including any cookies from login page)
        rsa_params = self.params.copy()
        if 'headers' in rsa_params:
            rsa_params['headers'].update(rsa_headers)
        else:
            rsa_params['headers'] = rsa_headers

        # Request to GET /getRSAPublickKey (note the typo in "Publick")
        with requests.get(
            self.url + "/getRSAPublickKey", **rsa_params
        ) as r:
            logger.debug(f"RSA key request status: {r.status_code}")
            logger.debug(f"RSA key response: {r.text}")

            # Update session cookies from the RSA key request (if any)
            if r.cookies:
                if "cookies" not in self.params:
                    self.params["cookies"] = {}
                new_cookies = requests.utils.dict_from_cookiejar(r.cookies)
                self.params["cookies"].update(new_cookies)
                logger.debug(f"Updated session cookies after RSA key request: {self.params['cookies']}")

            if r.status_code != 200:
                logger.error(f"Failed to get RSA key: {r.status_code} - {r.text}")
                self.rsa_key = None
                self.encryption_required = False
            else:
                try:
                    response_json = r.json()
                    self.rsa_key = response_json.get("RSAPublicKey", None)
                    if self.rsa_key == "None":     # yes, the router can return a "None" str
                        self.rsa_key = None
                    logger.debug(f"RSA key obtained: {'YES' if self.rsa_key else 'NO'}")
                    if self.rsa_key:
                        logger.debug(f"RSA key length: {len(self.rsa_key)}")
                except Exception as e:
                    logger.error(f"Failed to parse RSA key response: {e}")
                    self.rsa_key = None

            self.encryption_required = bool(self.rsa_key)
            self.aes_key = os.urandom(32)  # 256-bit AES key
            self.iv = os.urandom(32)       # 32-byte IV to match browser behavior
            if self.encryption_required:
                logger.debug("Encryption enabled for router")
            else:
                logger.debug("Encryption NOT enabled - no RSA key available")

        # Try parameter set that matches browser's 112-byte encrypted size
        # Add common hidden form fields that might be present
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
        logger.debug("Logging in...")
        if self.encryption_required:
           login_json = self.encrypt_request(self.login_params)
           logger.debug("Using encrypted login data")
        else:
            login_json = json.dumps(self.login_params)
            logger.debug("Using unencrypted login data")

        logger.debug(f"Login URL: {self.url}/UserLogin")
        logger.debug(f"Login data length: {len(login_json)}")

        # Add headers that match browser request exactly
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

        # Ensure we're using the session cookies from the RSA key request
        logger.debug(f"Using session cookies for login: {login_params.get('cookies', 'None')}")

        # Send encrypted JSON as raw body data despite form content-type (router expectation)
        with requests.post(
            self.url + "/UserLogin", data=login_json.encode('utf-8'), **login_params
        ) as r:
            logger.debug(f"Login response status: {r.status_code}")
            logger.debug(f"Login response text: {r.text}")

            if r.status_code != 200:
                logger.error(f"Login failed with status {r.status_code}: {r.text}")
                return False

            # Update cookies with any new ones from login response
            if r.cookies:
                new_cookies = requests.utils.dict_from_cookiejar(r.cookies)
                if "cookies" not in self.params:
                    self.params["cookies"] = {}
                self.params["cookies"].update(new_cookies)
                logger.debug(f"Updated cookies after login: {self.params['cookies']}")

            try:
                if self.encryption_required:
                    response_data = self.decrypt_response(r.json())
                    self.sessionkey = response_data["sessionkey"]
                else:
                    response_data = r.json()
                    self.sessionkey = response_data["sessionkey"]
                logger.debug(f"Session key: {self.sessionkey}")
                return True
            except Exception as e:
                logger.error(f"Failed to extract session key: {e}")
                return False

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
                            logger.debug(f"Successfully got {endpoint} data")
                    except requests.exceptions.HTTPError as e:
                        if e.response.status_code == 404:
                            logger.debug(f"Endpoint {endpoint} not available (404)")
                        elif e.response.status_code == 401:
                            # Re-raise 401 to trigger login retry
                            raise
                        else:
                            logger.debug(f"Endpoint {endpoint} failed: {e}")
                    except Exception as e:
                        logger.debug(f"Endpoint {endpoint} failed with exception: {e}")

                if successful_endpoints > 0:
                    logger.debug(f"Retrieved data from {successful_endpoints} endpoints")
                    return result
                else:
                    logger.error("No data could be retrieved from any endpoint")

            except requests.exceptions.HTTPError as e:
                logger.warn(f"HTTP Error: {e}")
                if e.response.status_code == 401:
                    # Unauthorized
                    logger.info("401 Unauthorized - attempting login")
                    login_success = self.login()
                    if not login_success:
                        logger.error("Login failed, cannot continue")
                        break
                elif e.response.status_code == 500:
                    logger.info(
                        "Internal server error received. Retrying without cookies."
                    )
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
                    logger.info(f"Endpoint {endpoint}: AVAILABLE")
                else:
                    logger.info(f"Endpoint {endpoint}: NO DATA")
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    logger.info(f"Endpoint {endpoint}: NOT FOUND (404)")
                elif e.response.status_code == 401:
                    logger.info(f"Endpoint {endpoint}: UNAUTHORIZED (401)")
                else:
                    logger.info(f"Endpoint {endpoint}: ERROR {e.response.status_code}")
            except Exception as e:
                logger.info(f"Endpoint {endpoint}: EXCEPTION {e}")

        logger.info(f"Available endpoints: {available_endpoints}")
        return available_endpoints

    def get_json_object(self, oid):
        url = self.url + "/cgi-bin/DAL?oid=" + oid
        logger.debug(f"Getting JSON object from: {url}")

        with requests.get(url, **self.params) as r:
            logger.debug(f"Response status: {r.status_code}")
            logger.debug(f"Response text: {r.text[:500]}...")  # First 500 chars

            r.raise_for_status()

            try:
                if self.encryption_required:
                    j = self.decrypt_response(r.json())
                else:
                    j = r.json()

                logger.debug(f"JSON response result: {j.get('result', 'NO_RESULT')}")

                if j.get("result") != "ZCFG_SUCCESS":
                    logger.warning(f"API returned non-success result: {j.get('result')}")
                    return None

                if not j.get("Object"):
                    logger.debug("No Object in response")
                    return None

                return j["Object"][0]

            except Exception as e:
                logger.error(f"Error processing JSON response: {e}")
                raise

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
        logger.debug(f"Encrypting request data: {json_data}")
        # Use compact JSON formatting to match browser behavior
        json_body = json.dumps(json_data, separators=(',', ':')).encode('utf-8')
        logger.debug(f"JSON body: {json_body}")
        logger.debug(f"JSON body length: {len(json_body)}")

        padded = pad(json_body, 16)
        logger.debug(f"Padded data length: {len(padded)}")

        # Encrypt the login parameters using AES (use only first 16 bytes of IV for CBC)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv[:16])
        ciphertext = cipher.encrypt(padded)
        content_b64 = base64.b64encode(ciphertext).decode()
        logger.debug(f"AES encrypted content length: {len(content_b64)}")

        try:
            rsa_key = RSA.import_key(self.rsa_key.encode('utf-8'))
            cipher_rsa = PKCS1_v1_5.new(rsa_key)

            # Fix: encrypt the base64-encoded AES key (this was the breakthrough!)
            base64_encoded_key = base64.b64encode(self.aes_key)
            encrypted_key = cipher_rsa.encrypt(base64_encoded_key)
            key_b64 = base64.b64encode(encrypted_key).decode()
            logger.debug(f"RSA encrypted key length: {len(key_b64)}")

            iv_b64 = base64.b64encode(self.iv).decode()
            logger.debug(f"IV base64 length: {len(iv_b64)}")

            result = json.dumps({
                "content": content_b64,
                "key": key_b64,
                "iv": iv_b64
            })
            logger.debug(f"Final encrypted request length: {len(result)}")
            return result

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def decrypt_response(self, encrypted_json: dict) -> dict:
        # Decode base64 values
        response_iv_b64 = encrypted_json["iv"]
        response_iv = base64.b64decode(response_iv_b64)
        ciphertext = base64.b64decode(encrypted_json["content"])

        logger.debug(f"Response IV (base64): {response_iv_b64}")
        logger.debug(f"Response IV (decoded): {len(response_iv)} bytes")
        logger.debug(f"Encrypted content: {len(ciphertext)} bytes")

        # Use the response IV for decryption (first 16 bytes for AES-CBC)
        iv_for_decrypt = response_iv[:16]
        logger.debug(f"Using IV for decryption: {iv_for_decrypt[:8].hex()}...")

        # Decrypt with AES (CBC mode) using the same key as request encryption
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv_for_decrypt)
        decrypted_padded = cipher.decrypt(ciphertext)
        logger.debug(f"Decrypted (with padding): {len(decrypted_padded)} bytes")

        # Try standard unpadding first
        try:
            decrypted_data = unpad(decrypted_padded, 16)
            logger.debug(f"Standard unpadding successful: {len(decrypted_data)} bytes")
        except ValueError as e:
            logger.debug(f"Standard unpadding failed: {e}")
            # Some routers (like EX5601-T0) may not use proper PKCS7 padding
            # Try removing null bytes or manual padding removal
            try:
                # Remove trailing null bytes
                decrypted_data = decrypted_padded.rstrip(b'\x00')
                if len(decrypted_data) == len(decrypted_padded):
                    # No null bytes were removed, try manual PKCS7 unpadding
                    if len(decrypted_padded) > 0:
                        padding_length = decrypted_padded[-1]
                        if padding_length <= 16 and padding_length > 0:
                            decrypted_data = decrypted_padded[:-padding_length]
                        else:
                            decrypted_data = decrypted_padded
                    else:
                        decrypted_data = decrypted_padded
                logger.debug(f"Manual unpadding successful: {len(decrypted_data)} bytes")
            except Exception as manual_error:
                logger.debug(f"Manual unpadding also failed: {manual_error}")
                # Last resort: use raw decrypted data
                decrypted_data = decrypted_padded

        # Try to decode and parse as JSON
        try:
            json_string = decrypted_data.decode("utf-8")
            logger.debug(f"Decoded JSON string: {json_string[:100]}...")
            return json.loads(json_string)
        except UnicodeDecodeError as ude:
            logger.error(f"Error processing JSON response: {ude}")
            logger.debug(f"Raw decrypted bytes (first 50): {decrypted_data[:50]}")
            logger.debug(f"Raw decrypted bytes (hex): {decrypted_data[:50].hex()}")
            raise Exception(f"Failed to decode decrypted response as UTF-8: {ude}")
        except json.JSONDecodeError as jde:
            logger.error(f"Error parsing JSON response: {jde}")
            logger.debug(f"Attempted to parse: {decrypted_data[:200]}")
            raise Exception(f"Failed to parse decrypted response as JSON: {jde}")
