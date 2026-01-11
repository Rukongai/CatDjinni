# Cat Genie API Signature Algorithm

## Status: FULLY REVERSE ENGINEERED

Working Python implementation: `catgenie_api.py`
Working API client: `catgenie_client.py`

---

## The 84-Character Secret

Extracted from Android Keychain via Frida (hooking `Cipher.doFinal`):

```
getyourownsecret
```

- Stored in React Native Keychain (encrypted with Android Keystore)
- Retrieved via `getGenericPassword()` call
- This appears to be per-user/per-account (generated at account creation)

---

## Derivation Parameters

Found in React Native bundle (`S()` function):

| Environment | Parameter String | Index | Prefix | Suffix |
|-------------|------------------|-------|--------|--------|
| dev | `0-1b-Mg` | 0 | `1b` | `Mg` |
| staging | `28-wq-0C` | 28 | `wq` | `0C` |
| **production** | `56-Yt-x3` | 56 | `Yt` | `x3` |

---

## HMAC Key Derivation

```
HMAC_KEY = prefix + secret[index:index+28] + suffix
```

For production:
```python
secret = "getyourownsecret"
index = 56
prefix = "Yt"
suffix = "x3"

extracted = secret[56:84]  # "nu5XPMENDE25FPFEFVR2UsrFwt" (28 chars)
HMAC_KEY = "Yt" + "nu5XPMENDE25FPFEFVR2UsrFwt" + "x3"
         = "Ytnu5XPMENDE25FPFEFVR2UsrFwtx3"  # 32 characters
```

Final HMAC key is always 32 characters (2 + 28 + 2).

---

## Request Headers

| Header | Description | Example |
|--------|-------------|---------|
| `x-pm-en-dec` | AES-encrypted timestamp (Base64) | `Ux8J5K...` |
| `x-pm-en-ver` | Version string | `1.0.0` |
| `x-render-t` | Path + timestamp | `device/device/v2/1704825600000` |
| `y-pm-sg-b` | Body signature (HMAC-SHA256 hex) | `a1b2c3...` |
| `y-pm-sg-p` | Params signature (HMAC-SHA256 hex) | `d4e5f6...` |
| `Authorization` | JWT Bearer token | `Bearer eyJ...` |

---

## Signature Generation Algorithm

### 1. Generate timestamp
```python
timestamp = int(time.time() * 1000)  # Unix ms
```

### 2. Build x-render-t
```python
path_clean = path.lstrip('/')
render_t = f"{path_clean}/{timestamp}"
```

### 3. Serialize body data (for POST/PUT/PATCH)
```python
def serialize_data(data: dict) -> str:
    if not data:
        return ""

    # Sort keys in REVERSE alphabetical order
    sorted_keys = sorted(data.keys(), reverse=True)
    result = ""

    for key in sorted_keys:
        value = data.get(key)
        if value is not None and key != "imageContent":
            result += str(value)

    # Remove spaces and convert to lowercase
    return result.replace(" ", "").lower()
```

### 4. Generate signatures
```python
# Body signature (y-pm-sg-b)
body_data = serialize_data(body) + render_t
sig_body = hmac.new(hmac_key.encode(), body_data.encode(), hashlib.sha256).hexdigest()

# Params signature (y-pm-sg-p)
params_data = serialize_data(params) + render_t
sig_params = hmac.new(hmac_key.encode(), params_data.encode(), hashlib.sha256).hexdigest()
```

---

## x-pm-en-dec Header (AES Encryption)

### AES Key
```
P-3Rp6d81Kw9a3Z-CyvWH0WXRieyITk6
```

This is constructed from:
- Static prefix: `P-3Rp6d81Kw9a3Z-`
- getMessage('vyC') result: `CyvWH0WXRieyITk6`

The `getMessage()` function:
```javascript
e.getMessage = function(I) {
    return ("eiRXW0HW" + I).split('').reverse().join('') + 'yITk6'
}
// getMessage('vyC') => "CyvWH0WXRieyITk6"
```

### Encryption Algorithm
```python
def generate_enc_dec_header(timestamp: int) -> str:
    # Adjust timestamp for even/odd check
    if (timestamp // 100) % 2 != 0:
        timestamp += 100

    # Generate random part with 'Z' inserted at random position
    random_part = random_string(7)  # 7 alphanumeric chars
    random_part = insert_char_at_random_position(random_part, 'Z')

    plaintext = f"{timestamp}-{random_part}"

    # AES-CBC encrypt with zero IV
    key = "P-3Rp6d81Kw9a3Z-CyvWH0WXRieyITk6".encode('utf-8')
    iv = b'\x00' * 16

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode('utf-8'), 16)  # PKCS7 padding
    encrypted = cipher.encrypt(padded)

    return base64.b64encode(encrypted).decode('utf-8')
```

---

## API Base URL

```
https://iot.petnovations.com
```

---

## JWT Token

Captured via Frida from HTTP requests. Tokens are RS512 signed and contain:
- `accountId`
- `tenantId`
- `scopes` (permissions list)
- `exp` (expiration)

Tokens can be refreshed but the refresh endpoint hasn't been fully mapped.

---

## Working API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `device/device/v2?useFleetIndexAndGetRealConnectivity=true` | List devices |
| GET | `notification/v1/push/user` | Get push notifications |
| GET | `notification/v1/notification/user` | Get all notifications |
| GET | `device/history/account/pet/statistics` | Pet usage stats |
| GET | `ums/v1/users/account` | Account info |
| GET | `device/update/{manufacturerId}` | Device update info |
| GET | `device/update/versions/comments` | Firmware version notes |
| GET | `device/v1/thing/{manufacturerId}` | Device thing info |
| GET | `device/mainBoard/{manufacturerId}` | Mainboard info |

---

## Obfuscation Functions (Reference)

Header names are reversed in the bundle:
```javascript
$("T-redneR-X")  // => "x-render-t"
$("B-GS-MP-Y")  // => "y-pm-sg-b"
$("P-GS-MP-Y")  // => "y-pm-sg-p"
```

The `f3` transformation function:
```javascript
e.f3 = function(t) {
    return t.replace(/A/g,"9")
            .replace(/e,/g,"r")
            .replace(/,/g,"2")
            .replace(/-/g,"F")
}
```

---

## Firmware Delivery

Firmware is **NOT** downloaded via HTTP URLs. It is:
1. Pushed via AWS IoT MQTT to the device
2. Device connects to: `a3onwma0mol7io.iot.us-east-1.amazonaws.com`
3. Firmware stored encrypted on external flash with `CGFW` header

This means we cannot intercept unencrypted firmware via the API or network sniffing.

---

## Files

- `catgenie_api.py` - Signature generation library
- `catgenie_client.py` - Full API client with all endpoints
- `frida-scripts/catgenie-keychain-v3.js` - Script that extracted the 84-char secret
- `frida-scripts/capture-auth-v2.js` - Script that captured HTTP headers and JWT

---

## Revision History

- Initial discovery: Frida hooks on NetworkingModule + React Native bundle analysis
- Secret extraction: Hooked `Cipher.doFinal` in Android Keychain decryption
- Full implementation: Python client successfully authenticates and queries API
