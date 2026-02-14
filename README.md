# 🍪 Flask Session Tool

! FULLY VIBECODED during a CTF.

**Like [jwt.io](https://jwt.io) — but for Flask session cookies.**

A 100% client-side web tool to **decode**, **encode**, **verify**, and **brute-force** Flask/itsdangerous session cookies. No server, no data leaves your browser.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Decode** | Paste any Flask session cookie → see the JSON payload, timestamp, and structure |
| 🔏 **Encode & Sign** | Create a forged session cookie with any payload + secret key |
| ✅ **Verify** | Check if a secret key matches a cookie's signature |
| 🔓 **Brute-force** | Crack the secret key using built-in wordlist, custom list, or uploaded file |
| 🎨 **Color-coded** | Cookie parts (payload, timestamp, signature) are color-highlighted |

## 🛡️ Security

- **100% client-side** — all crypto runs in your browser via the Web Crypto API
- **No tracking, no analytics, no cookies** (ironic, I know)
- Safe for CTF competitions and security research

## 🧪 How Flask Sessions Work

Flask uses `itsdangerous.URLSafeTimedSerializer` to sign session cookies:

```
[.]<payload_base64>.<timestamp_base64>.<hmac_signature>
```

- Leading `.` = payload is zlib-compressed
- Signature = `HMAC-SHA1(derived_key, payload + "." + timestamp)`
- Key derivation = `HMAC-SHA1(secret_key, "cookie-session")`

The cookie is **signed but not encrypted** — anyone can read the payload, but only someone with the secret key can forge a valid signature.