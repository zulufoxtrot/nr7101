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

        logger.debug("Attempting to get RSA public key...")

        # Add headers that match what the browser sends
        rsa_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-GB,en;q=0.5',
            'X-Requested-With': 'XMLHttpRequest',
            'If-Modified-Since': 'Thu, 01 Jun 1970 00:00:00 GMT',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0'
        }

        # Merge with existing params
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
            self.iv = os.urandom(16)       # 256-bit IV (some routers use 16 bytes; match what router expects)
            if self.encryption_required:
                logger.debug("Encryption enabled for router")
            else:
                logger.debug("Encryption NOT enabled - no RSA key available")

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
        logger.debug("Logging in...")
        if self.encryption_required:
           login_json = self.encrypt_request(self.login_params)
           logger.debug("Using encrypted login data")
        else:
            login_json = json.dumps(self.login_params)
            logger.debug("Using unencrypted login data")

        logger.debug(f"Login URL: {self.url}/UserLogin")
        logger.debug(f"Login data length: {len(login_json)}")

        # Add headers that match browser request
        login_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
            'If-Modified-Since': 'Thu, 01 Jun 1970 00:00:00 GMT',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0'
        }

        login_params = self.params.copy()
        if 'headers' in login_params:
            login_params['headers'].update(login_headers)
        else:
            login_params['headers'] = login_headers

        with requests.post(
            self.url + "/UserLogin", data=login_json, **login_params
        ) as r:
            logger.debug(f"Login response status: {r.status_code}")
            logger.debug(f"Login response text: {r.text}")

            if r.status_code != 200:
                logger.error(f"Login failed with status {r.status_code}: {r.text}")
                return False

            # Update cookies
            self.params["cookies"] = requests.utils.dict_from_cookiejar(r.cookies)
            logger.debug(f"Cookies received: {self.params['cookies']}")

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
        json_body = json.dumps(json_data).encode('utf-8')
        logger.debug(f"JSON body length: {len(json_body)}")

        padded = pad(json_body, 16)
        logger.debug(f"Padded data length: {len(padded)}")

        # Encrypt the login parameters using AES
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        ciphertext = cipher.encrypt(padded)
        content_b64 = base64.b64encode(ciphertext).decode()
        logger.debug(f"AES encrypted content length: {len(content_b64)}")

        try:
            rsa_key = RSA.import_key(self.rsa_key.encode('utf-8'))
            cipher_rsa = PKCS1_v1_5.new(rsa_key)

            # Fix: encrypt the raw AES key, not the base64 encoded version
            encrypted_key = cipher_rsa.encrypt(self.aes_key)
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
