/**
 * Flask Session Tool — UI Application Logic
 * jwt.io-style: live bidirectional sync between encoded ↔ decoded
 */

document.addEventListener('DOMContentLoaded', () => {

    // ─── Tab switching ────────────────────────────────────────────────

    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
        });
    });

    // ─── Editor Elements ──────────────────────────────────────────────

    const encodedInput   = document.getElementById('encoded-input');
    const decodedInput   = document.getElementById('decoded-input');
    const secretKey      = document.getElementById('secret-key');
    const compressOpt    = document.getElementById('compress-option');
    const saltOpt        = document.getElementById('salt-option');
    const verifyBanner   = document.getElementById('verify-banner');
    const verifyIcon     = document.getElementById('verify-icon');
    const verifyText     = document.getElementById('verify-text');
    const cookieInfo     = document.getElementById('cookie-info');

    // Prevent feedback loops
    let syncing = false;

    // ─── Encoded → Decoded (user pastes/types a cookie) ───────────────

    async function onEncodedChange() {
        if (syncing) return;
        const cookie = encodedInput.value.trim();

        if (!cookie) {
            syncing = true;
            decodedInput.value = '';
            syncing = false;
            cookieInfo.textContent = '—';
            setBanner('neutral', '🔑', 'Enter a secret key to verify or forge cookies');
            return;
        }

        try {
            const result = await FlaskSession.decode(cookie);

            syncing = true;
            decodedInput.value = JSON.stringify(result.payload, null, 2);
            syncing = false;

            // Update info
            const infoLines = [];
            infoLines.push(result.compressed ? '📦 Compressed (zlib)' : '📄 Uncompressed');
            infoLines.push('🕐 ' + result.timestampDate.toLocaleString());
            infoLines.push('📏 ' + result.payloadRaw.length + ' bytes');
            cookieInfo.innerHTML = infoLines.map(l => `<div>${l}</div>`).join('');

            // Verify if secret is set
            await verifySignature(cookie);

        } catch (err) {
            syncing = true;
            decodedInput.value = '';
            syncing = false;
            cookieInfo.textContent = '—';
            setBanner('invalid', '❌', 'Invalid cookie: ' + err.message);
        }
    }

    // ─── Decoded → Encoded (user edits the JSON payload) ──────────────

    async function onDecodedChange() {
        if (syncing) return;
        const json = decodedInput.value.trim();
        const secret = secretKey.value.trim();

        if (!json) {
            syncing = true;
            encodedInput.value = '';
            syncing = false;
            cookieInfo.textContent = '—';
            setBanner('neutral', '🔑', 'Enter a secret key to verify or forge cookies');
            return;
        }

        // Validate JSON
        try {
            JSON.parse(json);
        } catch {
            setBanner('invalid', '⚠️', 'Invalid JSON — fix the payload to re-encode');
            return;
        }

        if (!secret) {
            setBanner('neutral', '🔑', 'Enter a secret key to sign the cookie');
            return;
        }

        try {
            const cookie = await FlaskSession.encode(json, secret, {
                compress: compressOpt.checked,
                salt: saltOpt.value || 'cookie-session',
            });

            syncing = true;
            encodedInput.value = cookie;
            syncing = false;

            // Update info
            const result = await FlaskSession.decode(cookie);
            const infoLines = [];
            infoLines.push(result.compressed ? '📦 Compressed (zlib)' : '📄 Uncompressed');
            infoLines.push('🕐 ' + result.timestampDate.toLocaleString());
            infoLines.push('📏 ' + result.payloadRaw.length + ' bytes');
            cookieInfo.innerHTML = infoLines.map(l => `<div>${l}</div>`).join('');

            setBanner('valid', '✅', 'Signature valid — cookie is signed with your secret key');

        } catch (err) {
            setBanner('invalid', '❌', 'Encoding error: ' + err.message);
        }
    }

    // ─── Secret key change → re-verify or re-encode ───────────────────

    async function onSecretChange() {
        const cookie = encodedInput.value.trim();
        const json = decodedInput.value.trim();
        const secret = secretKey.value.trim();

        if (!secret) {
            setBanner('neutral', '🔑', 'Enter a secret key to verify or forge cookies');
            return;
        }

        // If there's a cookie, verify it
        if (cookie) {
            await verifySignature(cookie);
        }

        // If there's valid JSON, re-encode
        if (json) {
            try {
                JSON.parse(json);
                await onDecodedChange();
            } catch { /* invalid JSON, skip */ }
        }
    }

    // ─── Verify a cookie's signature ──────────────────────────────────

    async function verifySignature(cookie) {
        const secret = secretKey.value.trim();
        if (!secret) {
            setBanner('neutral', '🔑', 'Enter a secret key to verify the signature');
            return;
        }

        try {
            const result = await FlaskSession.verify(cookie, secret, saltOpt.value || 'cookie-session');
            if (result.valid) {
                setBanner('valid', '✅', 'Signature verified — secret key is correct');
            } else {
                setBanner('invalid', '❌', 'Invalid signature — wrong secret key');
            }
        } catch (err) {
            setBanner('invalid', '⚠️', 'Verification error: ' + err.message);
        }
    }

    // ─── Banner helper ────────────────────────────────────────────────

    function setBanner(state, icon, text) {
        verifyBanner.className = 'verify-banner ' + state;
        verifyIcon.textContent = icon;
        verifyText.textContent = text;
    }

    // ─── Wire up live events ──────────────────────────────────────────

    encodedInput.addEventListener('input', debounce(onEncodedChange, 250));
    decodedInput.addEventListener('input', debounce(onDecodedChange, 400));
    secretKey.addEventListener('input', debounce(onSecretChange, 300));
    compressOpt.addEventListener('change', () => onDecodedChange());
    saltOpt.addEventListener('input', debounce(onSecretChange, 400));

    // ─── Buttons ──────────────────────────────────────────────────────

    // Paste
    document.getElementById('paste-btn').addEventListener('click', async () => {
        try {
            const text = await navigator.clipboard.readText();
            encodedInput.value = text;
            onEncodedChange();
        } catch {
            encodedInput.focus();
        }
    });

    // Copy encoded cookie
    document.getElementById('copy-encoded').addEventListener('click', () => {
        const v = encodedInput.value.trim();
        if (v) {
            navigator.clipboard.writeText(v);
            showToast('Cookie copied!');
        }
    });

    // Copy decoded JSON (minified)
    document.getElementById('copy-decoded').addEventListener('click', () => {
        const v = decodedInput.value.trim();
        if (v) {
            try {
                const minified = JSON.stringify(JSON.parse(v));
                navigator.clipboard.writeText(minified);
                showToast('JSON copied (minified)!');
            } catch {
                navigator.clipboard.writeText(v);
                showToast('Text copied!');
            }
        }
    });

    // Format JSON
    document.getElementById('format-json').addEventListener('click', () => {
        try {
            const parsed = JSON.parse(decodedInput.value);
            decodedInput.value = JSON.stringify(parsed, null, 2);
        } catch {
            showToast('Invalid JSON — cannot format');
        }
    });

    // ─── BRUTE-FORCE TAB ──────────────────────────────────────────────

    const bruteBtn = document.getElementById('brute-btn');
    const bruteStopBtn = document.getElementById('brute-stop-btn');
    const bruteOutput = document.getElementById('brute-output');
    const bruteProgressContainer = document.getElementById('brute-progress');
    const bruteProgressFill = document.getElementById('brute-progress-fill');
    const bruteProgressText = document.getElementById('brute-progress-text');
    let bruteAbort = null;

    document.querySelectorAll('input[name="wordlist-src"]').forEach(radio => {
        radio.addEventListener('change', () => {
            document.getElementById('brute-wordlist').classList.toggle('hidden', radio.value !== 'custom');
            document.getElementById('brute-file').classList.toggle('hidden', radio.value !== 'file');
        });
    });

    bruteBtn.addEventListener('click', async () => {
        const cookie = document.getElementById('brute-cookie').value.trim();
        if (!cookie) {
            bruteOutput.innerHTML = '<p class="error">❌ Please enter a session cookie</p>';
            return;
        }

        const src = document.querySelector('input[name="wordlist-src"]:checked').value;
        let wordlist = [];

        if (src === 'builtin') {
            wordlist = [...FlaskSession.COMMON_SECRETS];
        } else if (src === 'custom') {
            wordlist = document.getElementById('brute-wordlist').value.split('\n').filter(l => l.trim());
        } else if (src === 'file') {
            const file = document.getElementById('brute-file').files[0];
            if (!file) {
                bruteOutput.innerHTML = '<p class="error">❌ Please select a wordlist file</p>';
                return;
            }
            const text = await file.text();
            wordlist = text.split('\n').filter(l => l.trim());
        }

        if (wordlist.length === 0) {
            bruteOutput.innerHTML = '<p class="error">❌ Wordlist is empty</p>';
            return;
        }

        try {
            const decoded = await FlaskSession.decode(cookie);
            bruteOutput.innerHTML = `
                <p>🔍 Decoded payload:</p>
                <pre><code>${syntaxHighlight(JSON.stringify(decoded.payload, null, 2))}</code></pre>
                <p>⏳ Trying ${wordlist.length.toLocaleString()} secrets...</p>
            `;
        } catch (err) {
            bruteOutput.innerHTML = `<p class="error">❌ Invalid cookie: ${escapeHtml(err.message)}</p>`;
            return;
        }

        bruteBtn.classList.add('hidden');
        bruteStopBtn.classList.remove('hidden');
        bruteProgressContainer.classList.remove('hidden');
        bruteAbort = new AbortController();
        const startTime = Date.now();

        const found = await FlaskSession.bruteForce(
            cookie, wordlist,
            (checked, total) => {
                const pct = Math.round((checked / total) * 100);
                bruteProgressFill.style.width = pct + '%';
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                const rate = Math.round(checked / (elapsed || 1));
                bruteProgressText.textContent = `${checked.toLocaleString()} / ${total.toLocaleString()} (${rate}/s) — ${elapsed}s`;
            },
            (secret, attempts) => {
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                bruteOutput.innerHTML = `
                    <div class="found-result">
                        <p class="success">🔓 Secret key found!</p>
                        <div class="found-key">
                            <span class="label">Secret:</span>
                            <code class="big-key">${escapeHtml(secret)}</code>
                            <button class="btn-small copy-key-btn" title="Copy key">📄</button>
                        </div>
                        <p class="meta">Found after ${attempts.toLocaleString()} attempts in ${elapsed}s</p>
                    </div>
                `;
                document.querySelector('.copy-key-btn')?.addEventListener('click', () => {
                    navigator.clipboard.writeText(secret);
                    showToast('Secret key copied!');
                });
            },
            bruteAbort.signal,
        );

        if (!found) {
            const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
            if (bruteAbort.signal.aborted) {
                bruteOutput.innerHTML += `<p class="warning">⏹ Stopped after ${elapsed}s</p>`;
            } else {
                bruteOutput.innerHTML += `<p class="warning">❌ No key found in ${wordlist.length.toLocaleString()} attempts (${elapsed}s)</p>`;
            }
        }

        bruteBtn.classList.remove('hidden');
        bruteStopBtn.classList.add('hidden');
    });

    bruteStopBtn.addEventListener('click', () => {
        if (bruteAbort) bruteAbort.abort();
    });

    // ─── Helpers ──────────────────────────────────────────────────────

    function escapeHtml(str) {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function syntaxHighlight(json) {
        json = escapeHtml(json);
        return json.replace(
            /("(\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
            (match) => {
                let cls = 'json-number';
                if (/^"/.test(match)) {
                    cls = /:$/.test(match) ? 'json-key' : 'json-string';
                } else if (/true|false/.test(match)) {
                    cls = 'json-boolean';
                } else if (/null/.test(match)) {
                    cls = 'json-null';
                }
                return `<span class="${cls}">${match}</span>`;
            }
        );
    }

    function debounce(fn, delay) {
        let timer;
        return (...args) => {
            clearTimeout(timer);
            timer = setTimeout(() => fn(...args), delay);
        };
    }

    function showToast(msg) {
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = msg;
        document.body.appendChild(toast);
        requestAnimationFrame(() => toast.classList.add('show'));
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 2000);
    }
});
