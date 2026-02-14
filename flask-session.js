/**
 * Flask Session Cookie Encoder/Decoder — Pure JavaScript
 *
 * Implements the itsdangerous URLSafeTimedSerializer used by Flask
 * for session cookies. Supports:
 *   - Decoding (base64 + optional zlib decompression)
 *   - Encoding (JSON → optional zlib → base64 → HMAC signature)
 *   - Signature verification
 *
 * Flask session format:
 *   [.]<payload_b64>.<timestamp_b64>.<signature_b64>
 *
 * Leading dot means the payload is zlib-compressed.
 */

const FlaskSession = (() => {

    // ─── Base64 URL-safe helpers ───────────────────────────────────────

    function b64Encode(uint8) {
        let binary = '';
        for (let i = 0; i < uint8.length; i++) {
            binary += String.fromCharCode(uint8[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    function b64Decode(str) {
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        const pad = (4 - (str.length % 4)) % 4;
        str += '='.repeat(pad);
        const binary = atob(str);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    // ─── Zlib helpers (using DecompressionStream / CompressionStream) ──

    async function zlibDecompress(data) {
        const ds = new DecompressionStream('deflate');
        const writer = ds.writable.getWriter();
        writer.write(data);
        writer.close();
        const reader = ds.readable.getReader();
        const chunks = [];
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
        }
        const totalLength = chunks.reduce((acc, c) => acc + c.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of chunks) {
            result.set(chunk, offset);
            offset += chunk.length;
        }
        return result;
    }

    async function zlibCompress(data) {
        // Browser's CompressionStream('deflate') produces zlib-format (RFC 1950)
        // which matches Python's zlib.compress() — includes header + checksum.
        const cs = new CompressionStream('deflate');
        const writer = cs.writable.getWriter();
        writer.write(data);
        writer.close();
        const reader = cs.readable.getReader();
        const chunks = [];
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
        }
        const totalLength = chunks.reduce((acc, c) => acc + c.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of chunks) {
            result.set(chunk, offset);
            offset += chunk.length;
        }
        return result;
    }

    // ─── HMAC-SHA1 via Web Crypto API ─────────────────────────────────

    function textToBytes(text) {
        return new TextEncoder().encode(text);
    }

    function bytesToText(bytes) {
        return new TextDecoder().decode(bytes);
    }

    async function hmacSha1(key, data) {
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            typeof key === 'string' ? textToBytes(key) : key,
            { name: 'HMAC', hash: 'SHA-1' },
            false,
            ['sign']
        );
        const sig = await crypto.subtle.sign(
            'HMAC',
            cryptoKey,
            typeof data === 'string' ? textToBytes(data) : data
        );
        return new Uint8Array(sig);
    }

    async function hmacSha512(key, data) {
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            typeof key === 'string' ? textToBytes(key) : key,
            { name: 'HMAC', hash: 'SHA-512' },
            false,
            ['sign']
        );
        const sig = await crypto.subtle.sign(
            'HMAC',
            cryptoKey,
            typeof data === 'string' ? textToBytes(data) : data
        );
        return new Uint8Array(sig);
    }

    // ─── itsdangerous key derivation ──────────────────────────────────
    // Flask uses HMAC key derivation by default:
    //   derived_key = HMAC-SHA512(secret_key, salt + "signer-sep" + "cookie-session")
    // Wait, actually:
    //   derived_key = HMAC-SHA1(key=secret_key, msg=salt)
    // where salt = "cookie-session" + "." + "signer"  (for the default URLSafeTimedSerializer)
    //
    // Actually the full derivation is:
    //   key = hmac(secret, salt)
    //   where salt = "{salt_value}{sep}{key_derivation}"
    //   default: salt_value="cookie-session", sep=".", key_derivation from signer
    //
    // In Flask's implementation:
    //   The signer uses key_derivation='hmac' and digest_method=hashlib.sha1
    //   derived = hmac.new(secret, salt_string, sha1).digest()
    //   where salt_string = salt + "." + "signer"   (salt="cookie-session")

    async function deriveKey(secret, salt = 'cookie-session') {
        // Flask's default: HMAC key derivation
        // The full salt string used is: salt + "." + "signer"  (the sep is .)
        // But actually looking at itsdangerous source:
        //   self.salt = want_bytes(salt) -> "cookie-session"
        //   In derive_key(): 
        //     mac = hmac.new(self.secret_key, digestmod=self.digest_method)
        //     mac.update(b"signer" if key_derivation == "django-concat" ...)
        //     For key_derivation == "hmac":
        //       mac = hmac.new(self.secret_key, digestmod=self.digest_method)
        //       mac.update(self.salt)
        //       return mac.digest()

        const secretBytes = typeof secret === 'string' ? textToBytes(secret) : secret;
        const saltBytes = typeof salt === 'string' ? textToBytes(salt) : salt;

        // HMAC-SHA1(key=secret, msg=salt)
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            secretBytes,
            { name: 'HMAC', hash: 'SHA-1' },
            false,
            ['sign']
        );
        const derived = await crypto.subtle.sign(
            'HMAC',
            cryptoKey,
            saltBytes
        );
        return new Uint8Array(derived);
    }

    // ─── Timestamp encoding (base62-ish used by itsdangerous) ─────────

    // itsdangerous < 2.0 used an epoch of 2011-01-01 (1293840000).
    // itsdangerous >= 2.0 uses raw Unix timestamps.
    // We auto-detect based on magnitude when decoding.
    const LEGACY_EPOCH = 1293840000;

    function intToBytes(num) {
        // Convert integer to big-endian bytes (variable length)
        if (num === 0) return new Uint8Array([0]);
        const bytes = [];
        while (num > 0) {
            bytes.unshift(num & 0xff);
            num = Math.floor(num / 256);
        }
        return new Uint8Array(bytes);
    }

    function bytesToInt(bytes) {
        let num = 0;
        for (let i = 0; i < bytes.length; i++) {
            num = num * 256 + bytes[i];
        }
        return num;
    }

    function getTimestamp() {
        // Use raw Unix timestamp (itsdangerous 2.x format)
        return Math.floor(Date.now() / 1000);
    }

    function timestampToDate(ts) {
        // Auto-detect: if ts < 1e9 it's legacy (epoch-relative), otherwise raw Unix
        if (ts < 1e9) {
            return new Date((ts + LEGACY_EPOCH) * 1000);
        }
        return new Date(ts * 1000);
    }

    // ─── Cookie Parsing ───────────────────────────────────────────────

    function parseCookie(cookie) {
        cookie = cookie.trim();

        let compressed = false;
        if (cookie.startsWith('.')) {
            compressed = true;
            cookie = cookie.substring(1);
        }

        // Split by '.' — the format is: payload.timestamp.signature
        const parts = cookie.split('.');
        if (parts.length < 3) {
            throw new Error(`Invalid cookie format: expected at least 3 dot-separated parts, got ${parts.length}`);
        }

        // The signature is the last part, timestamp is second-to-last
        const signature = parts[parts.length - 1];
        const timestamp = parts[parts.length - 2];
        const payload = parts.slice(0, parts.length - 2).join('.');

        return { compressed, payload, timestamp, signature };
    }

    // ─── Decode ───────────────────────────────────────────────────────

    async function decode(cookie) {
        const parsed = parseCookie(cookie);

        // Decode payload
        let payloadBytes = b64Decode(parsed.payload);

        if (parsed.compressed) {
            try {
                payloadBytes = await zlibDecompress(payloadBytes);
            } catch (e) {
                throw new Error('Failed to decompress payload: ' + e.message);
            }
        }

        const payloadStr = bytesToText(payloadBytes);

        let payloadJson;
        try {
            payloadJson = JSON.parse(payloadStr);
        } catch {
            payloadJson = payloadStr; // Not JSON — return as-is
        }

        // Decode timestamp
        const tsBytes = b64Decode(parsed.timestamp);
        const tsInt = bytesToInt(tsBytes);
        const date = timestampToDate(tsInt);

        return {
            compressed: parsed.compressed,
            payload: payloadJson,
            payloadRaw: payloadStr,
            timestamp: tsInt,
            timestampDate: date,
            signatureB64: parsed.signature,
            parts: parsed,
        };
    }

    // ─── Verify Signature ─────────────────────────────────────────────

    async function verify(cookie, secret, salt = 'cookie-session') {
        const parsed = parseCookie(cookie);

        // The signed value is: payload + "." + timestamp
        const value = parsed.payload + '.' + parsed.timestamp;

        // Derive key
        const key = await deriveKey(secret, salt);

        // Compute HMAC-SHA1 of the value
        const expectedSig = await hmacSha1(key, value);
        const expectedB64 = b64Encode(expectedSig);

        // Also handle the case where cookie starts with '.'
        let signedPayload = parsed.payload;
        if (cookie.trim().startsWith('.')) {
            signedPayload = '.' + parsed.payload;
        }
        const value2 = signedPayload + '.' + parsed.timestamp;
        const expectedSig2 = await hmacSha1(key, value2);
        const expectedB64_2 = b64Encode(expectedSig2);

        return {
            valid: parsed.signature === expectedB64 || parsed.signature === expectedB64_2,
            expectedSignature: expectedB64,
            actualSignature: parsed.signature,
        };
    }

    // ─── Encode & Sign ────────────────────────────────────────────────

    async function encode(payload, secret, options = {}) {
        const salt = options.salt || 'cookie-session';
        const compress = options.compress !== false; // default true

        // Serialize payload
        let payloadStr;
        if (typeof payload === 'string') {
            // Validate JSON
            try {
                JSON.parse(payload);
                payloadStr = payload;
            } catch {
                payloadStr = payload;
            }
        } else {
            payloadStr = JSON.stringify(payload, null, 0);
        }

        // Sort keys for consistency (Flask uses sorted keys by default)
        try {
            const parsed = JSON.parse(payloadStr);
            payloadStr = sortedStringify(parsed);
        } catch { /* keep as-is */ }

        let payloadBytes = textToBytes(payloadStr);
        let compressed = false;

        if (compress) {
            try {
                const compressedBytes = await zlibCompress(payloadBytes);
                if (compressedBytes.length < payloadBytes.length) {
                    payloadBytes = compressedBytes;
                    compressed = true;
                }
            } catch { /* skip compression */ }
        }

        const payloadB64 = b64Encode(payloadBytes);

        // Timestamp
        const ts = getTimestamp();
        const tsBytes = intToBytes(ts);
        const tsB64 = b64Encode(tsBytes);

        // Value to sign
        let valueToSign;
        if (compressed) {
            valueToSign = '.' + payloadB64 + '.' + tsB64;
        } else {
            valueToSign = payloadB64 + '.' + tsB64;
        }

        // Derive key and sign
        const key = await deriveKey(secret, salt);
        const sig = await hmacSha1(key, valueToSign);
        const sigB64 = b64Encode(sig);

        const cookie = valueToSign + '.' + sigB64;
        return cookie;
    }

    // Sorted JSON stringify (Flask serializes with sorted keys)
    function sortedStringify(obj) {
        if (obj === null || typeof obj !== 'object') {
            return JSON.stringify(obj);
        }
        if (Array.isArray(obj)) {
            return '[' + obj.map(sortedStringify).join(',') + ']';
        }
        const keys = Object.keys(obj).sort();
        const parts = keys.map(k => JSON.stringify(k) + ':' + sortedStringify(obj[k]));
        return '{' + parts.join(',') + '}';
    }

    // ─── Brute-force ──────────────────────────────────────────────────

    async function bruteForce(cookie, wordlist, onProgress, onFound, signal) {
        const parsed = parseCookie(cookie);

        let signedPayload = parsed.payload;
        if (cookie.trim().startsWith('.')) {
            signedPayload = '.' + parsed.payload;
        }
        const value = signedPayload + '.' + parsed.timestamp;
        const targetSig = parsed.signature;

        const total = wordlist.length;
        let checked = 0;

        for (const secret of wordlist) {
            if (signal && signal.aborted) {
                return null;
            }

            const trimmed = secret.trim();
            if (!trimmed) {
                checked++;
                continue;
            }

            try {
                const key = await deriveKey(trimmed);
                const sig = await hmacSha1(key, value);
                const sigB64 = b64Encode(sig);

                if (sigB64 === targetSig) {
                    onFound(trimmed, checked + 1);
                    return trimmed;
                }
            } catch { /* skip */ }

            checked++;
            if (checked % 100 === 0 || checked === total) {
                onProgress(checked, total);
                // Yield to UI
                await new Promise(r => setTimeout(r, 0));
            }
        }

        onProgress(total, total);
        return null;
    }

    // ─── Built-in wordlist (common Flask secrets) ─────────────────────

    const COMMON_SECRETS = [
        'secret', 'secret_key', 'secretkey', 'secret-key', 'supersecret',
        'supersecretkey', 'super-secret-key', 'super_secret_key',
        'mysecret', 'my-secret', 'my_secret', 'mysecretkey',
        'verysecretkey', 'very-secret-key', 'very_secret_key',
        'password', 'password1', 'password123', 'pass', 'passwd',
        'changeme', 'change_me', 'change-me', 'changethis',
        'default', 'flask', 'flask-secret', 'flask_secret',
        'flasksecret', 'flasksecretkey', 'flask-secret-key',
        'app', 'application', 'app-secret', 'app_secret',
        'dev', 'development', 'debug', 'test', 'testing', 'production',
        'hackme', 'hackmeplz', 'admin', 'letmein', 'welcome',
        'key', 'mykey', 'my-key', 'my_key',
        's3cr3t', 's3cret', 'secr3t', 's3cr3tk3y',
        '12345', '123456', '1234567', '12345678', '123456789',
        'qwerty', 'abc123', 'monkey', 'master', 'dragon', 'shadow',
        'iloveyou', 'trustno1', 'whatever', 'freedom', 'hello',
        'asdf', 'asdfgh', 'asdfghjkl', 'zxcvbnm',
        'sk', 'sk-key', 'secret123', 'key123', 'flask123',
        'thisisasecret', 'this-is-a-secret', 'this_is_a_secret',
        'T0pS3cr3t', 'topsecret', 'top-secret', 'top_secret',
        'notsecret', 'not-secret', 'not_secret', 'insecure',
        'keyboard', 'qwertyuiop', 'baseball', 'football',
        'CHANGEME', 'SECRET', 'SECRET_KEY', 'PASSWORD',
        'you-will-never-guess', 'hard-to-guess', 'hardtoguess',
        'random-secret-key', 'random_secret_key', 'randomsecretkey',
        'my-flask-secret', 'my_flask_secret', 'myflasksecret',
        'session-secret', 'session_secret', 'sessionsecret',
        'cookie-secret', 'cookie_secret', 'cookiesecret',
        'unsafe-secret', 'unsafe', 'temp', 'temporary',
        'replace-me', 'replace_me', 'replaceme', 'fixme',
        'todo-change', 'todo_change', 'todochange',
        'WjjFzKEV2C', 'p@ssw0rd', 'P@ssw0rd', 'P@ssword1',
        'sUp3rS3cr3t!', 'D0ntGuessM3',
        'thisismysecretkey', 'this_is_my_secret_key',
    ];

    // ─── Public API ───────────────────────────────────────────────────

    return {
        decode,
        encode,
        verify,
        bruteForce,
        parseCookie,
        COMMON_SECRETS,
        b64Encode,
        b64Decode,
        timestampToDate,
    };

})();
