#!/usr/bin/env python3
"""
Cat Genie API Signature Generator

Generates valid signatures for the Cat Genie mobile API.
Extracted from reverse engineering the React Native app.
"""

import hmac
import hashlib
import base64
import time
import random
import string
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


# The 84-character secret extracted from the Android Keychain via Frida
SECRET = ""

# Derivation parameters by environment: "index-prefix-suffix"
DERIVATION_PARAMS = {
    "dev": "0-1b-Mg",
    "staging": "28-wq-0C",
    "production": "56-Yt-x3"
}

# AES encryption key for x-pm-en-dec header
# Computed from: "P-3Rp6d81Kw9a3Z-CyvWH0WXRieyITk6"
AES_KEY = "P-3Rp6d81Kw9a3Z-CyvWH0WXRieyITk6"


def derive_hmac_key(secret: str, environment: str = "production") -> str:
    """
    Derive the 32-character HMAC key from the 84-char secret.

    Algorithm: prefix + secret[index:index+28] + suffix
    """
    params = DERIVATION_PARAMS.get(environment, DERIVATION_PARAMS["production"])
    parts = params.split("-")
    index = int(parts[0])
    prefix = parts[1]
    suffix = parts[2]

    extracted = secret[index:index + 28]
    return prefix + extracted + suffix


def serialize_data(data: dict) -> str:
    """
    Serialize request data for signing.

    Algorithm:
    1. Sort keys in reverse alphabetical order
    2. Concatenate all values (skip null and 'imageContent')
    3. Remove spaces and convert to lowercase
    """
    if not data:
        return ""

    sorted_keys = sorted(data.keys(), reverse=True)
    result = ""

    for key in sorted_keys:
        value = data.get(key)
        if value is not None and key != "imageContent":
            result += str(value)

    return result.replace(" ", "").lower()


def generate_signature(key: str, data: str) -> str:
    """
    Generate HMAC-SHA256 signature.

    The crypto-js library uses HmacSHA256(message, key).toString()
    which outputs lowercase hex.
    """
    signature = hmac.new(
        key.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return signature


def random_string(length: int) -> str:
    """Generate random alphanumeric string."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def insert_char(s: str, char: str) -> str:
    """Insert a character at random position in string."""
    pos = random.randint(0, len(s))
    return s[:pos] + char + s[pos:]


def generate_enc_dec_header(timestamp: int) -> str:
    """
    Generate the x-pm-en-dec header value.

    Algorithm:
    1. If (timestamp/100 % 2 != 0), add 100 to timestamp
    2. Create string: modified_timestamp + '-' + random_with_Z
    3. AES-CBC encrypt with key and zero IV
    4. Return Base64
    """
    # Adjust timestamp
    if (timestamp // 100) % 2 != 0:
        timestamp += 100

    # Generate random part with 'Z' inserted
    random_part = random_string(7)
    random_part = insert_char(random_part, 'Z')

    plaintext = f"{timestamp}-{random_part}"

    # AES-CBC encrypt with zero IV
    key = AES_KEY.encode('utf-8')
    iv = b'\x00' * 16

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded)

    return base64.b64encode(encrypted).decode('utf-8')


def generate_request_headers(
    path: str,
    method: str = "GET",
    body: dict = None,
    params: dict = None,
    environment: str = "production"
) -> dict:
    """
    Generate all required signature headers for a Cat Genie API request.

    Returns dict with:
    - x-pm-en-dec: Encrypted timestamp
    - x-pm-en-ver: Version (1.0.0)
    - x-render-t: path/timestamp
    - y-pm-sg-b: Body signature
    - y-pm-sg-p: Params signature
    """
    timestamp = int(time.time() * 1000)
    hmac_key = derive_hmac_key(SECRET, environment)

    # x-render-t: path/timestamp (no leading slash)
    path_clean = path.lstrip('/')
    render_t = f"{path_clean}/{timestamp}"

    # Serialize body data for POST/PUT/PATCH
    body_data = ""
    if method.upper() in ("POST", "PUT", "PATCH") and body:
        body_data = serialize_data(body)
    body_data += render_t

    # Serialize params
    params_data = ""
    if params:
        params_data = serialize_data(params)
    params_data += render_t

    # Generate signatures
    sig_body = generate_signature(hmac_key, body_data)
    sig_params = generate_signature(hmac_key, params_data)

    # Generate x-pm-en-dec
    enc_dec = generate_enc_dec_header(timestamp)

    return {
        "x-pm-en-dec": enc_dec,
        "x-pm-en-ver": "1.0.0",
        "x-render-t": render_t,
        "y-pm-sg-b": sig_body,
        "y-pm-sg-p": sig_params
    }


def main():
    """Test signature generation."""
    print("Cat Genie API Signature Generator")
    print("=" * 50)

    # Derive HMAC key
    hmac_key = derive_hmac_key(SECRET)
    print(f"\nDerived HMAC key: {hmac_key}")
    print(f"Key length: {len(hmac_key)} chars")

    # Test with a sample request
    path = "facade/v1/device"
    headers = generate_request_headers(path, "GET")

    print(f"\nTest headers for GET {path}:")
    for key, value in headers.items():
        print(f"  {key}: {value}")

    # Test with POST request
    body = {"deviceId": "test123"}
    headers_post = generate_request_headers(
        "facade/v1/device/command",
        "POST",
        body=body
    )

    print(f"\nTest headers for POST with body {body}:")
    for key, value in headers_post.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
