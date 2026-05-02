// ================== SECURITY CONFIG ==================
// HOW TO SET YOUR PASSWORD:
//   1. Open browser console on any HTTPS page
//   2. Run: generateCredential("yourpassword")
//   3. Paste the resulting CREDENTIAL object below.
//
// NEVER store a plain SHA-256 hash — it's brute-forceable in seconds.
// PBKDF2 (310,000 iterations) makes each guess take ~1 second on modern hardware.

const CREDENTIAL = {
  salt: "772ee2043a0f9699371ed7e2c650ef06",
  hash: "87df992fec2c478c94eb5f9f0df3af1c3c49134abf0e2c2aba21fb539f9fe569",
};

const MAX_ATTEMPTS   = 5;
const LOCK_DURATION  = 15 * 60 * 1000;
const MAX_PW_LENGTH  = 128;
const PBKDF2_ITERS   = 310_000;
const TOKEN_TTL      = 8 * 60 * 60 * 1000;

const SK_TOKEN    = "auth_token";
const SK_ATTEMPTS = "auth_attempts";
const SK_LOCK     = "auth_lock_until";

// ================== CRYPTO ==================

async function deriveKey(password, saltHex) {
  const enc    = new TextEncoder();
  const salt   = hexToBytes(saltHex);
  const keyMat = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERS },
    keyMat, 256
  );
  return bytesToHex(new Uint8Array(bits));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ 0;
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function randomHex(bytes = 16) {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function hmacSign(key, data) {
  const enc       = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(data));
  return bytesToHex(new Uint8Array(sig));
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ================== TOKEN MANAGEMENT ==================

let SESSION_KEY = null;

function getSessionKey() {
  if (!SESSION_KEY) SESSION_KEY = randomHex(32);
  return SESSION_KEY;
}

async function issueToken() {
  const expiry  = Date.now() + TOKEN_TTL;
  const payload = `${getSessionKey()}:${expiry}`;
  const sig     = await hmacSign(getSessionKey(), payload);
  sessionStorage.setItem(SK_TOKEN, JSON.stringify({ expiry, sig }));
}

async function verifyToken() {
  try {
    const raw = sessionStorage.getItem(SK_TOKEN);
    if (!raw) return false;
    const { expiry, sig } = JSON.parse(raw);
    if (Date.now() > expiry) { sessionStorage.removeItem(SK_TOKEN); return false; }
    const payload  = `${getSessionKey()}:${expiry}`;
    const expected = await hmacSign(getSessionKey(), payload);
    return timingSafeEqual(sig, expected);
  } catch { return false; }
}

// ================== LOCKOUT ==================

function getLockState() {
  const lock = sessionStorage.getItem(SK_LOCK);
  if (!lock) return { locked: false };
  const until = parseInt(lock, 10);
  if (Date.now() < until) return { locked: true, until };
  sessionStorage.removeItem(SK_LOCK);
  sessionStorage.removeItem(SK_ATTEMPTS);
  return { locked: false };
}

function recordFailedAttempt() {
  let attempts = parseInt(sessionStorage.getItem(SK_ATTEMPTS) || "0", 10) + 1;
  sessionStorage.setItem(SK_ATTEMPTS, String(attempts));
  if (attempts >= MAX_ATTEMPTS) {
    sessionStorage.setItem(SK_LOCK, String(Date.now() + LOCK_DURATION));
  }
  return attempts;
}

function clearAttempts() {
  sessionStorage.removeItem(SK_ATTEMPTS);
}

// ================== LOCK PAGE ==================

function lockPage() {
  document.documentElement.innerHTML =
    `<body style="background:#000;color:#ff4444;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">` +
    `<p style="font-size:1.2rem">⛔ SESSION TERMINATED</p></body>`;
}

// ================== CSP ==================

function injectCSP() {
  const meta = document.createElement("meta");
  meta.httpEquiv = "Content-Security-Policy";
  meta.content = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'none'",
    "object-src 'none'",
    "base-uri 'self'",
  ].join("; ");
  document.head.prepend(meta);
}

// ================== AUTH UI ==================

function renderLocked(until) {
  const remaining = Math.ceil((until - Date.now()) / 60000);
  document.body.innerHTML =
    `<div style="position:fixed;inset:0;background:#0a0a0a;display:flex;align-items:center;justify-content:center;font-family:monospace">` +
    `<div style="text-align:center;color:#ff4444">` +
    `<p style="font-size:1.5rem">⛔ LOCKED</p>` +
    `<p>Too many failed attempts.<br>Try again in ${remaining} minute${remaining !== 1 ? "s" : ""}.</p>` +
    `</div></div>`;
}

function createAuthModal() {
  const overlay = document.createElement("div");
  overlay.id = "auth-overlay";
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-label", "Authentication required");
  overlay.innerHTML = `
    <div style="
      position:fixed;inset:0;
      background:#0a0a0a;
      display:flex;justify-content:center;align-items:center;
      z-index:9999;">
      <div style="text-align:center;color:#00ff00;font-family:monospace;max-width:320px;width:90%">
        <h2 style="letter-spacing:.1em;margin-bottom:1.5rem">🔐 SECURE TERMINAL</h2>
        <input
          id="pw-input"
          type="password"
          autocomplete="current-password"
          placeholder="Enter password"
          maxlength="${MAX_PW_LENGTH}"
          style="
            width:100%;box-sizing:border-box;
            padding:10px;
            background:#111;color:#0f0;
            border:1px solid #0f0;
            font-family:monospace;font-size:1rem;
            outline:none;"
          aria-label="Password">
        <button
          id="pw-submit"
          style="
            margin-top:1rem;
            padding:8px 24px;
            background:#0f0;color:#000;
            border:none;cursor:pointer;
            font-family:monospace;font-size:1rem;font-weight:bold;">
          ENTER
        </button>
        <div id="pw-msg" role="alert" aria-live="polite" style="margin-top:1rem;min-height:1.2em;color:#ff4444;font-size:.9rem;"></div>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  return overlay;
}

// ================== MAIN ==================

async function startAuth() {
  injectCSP();

  const content = document.getElementById("terminal-content");
  if (content) content.style.display = "none";

  const lock = getLockState();
  if (lock.locked) { renderLocked(lock.until); return; }

  if (await verifyToken()) {
    if (content) content.style.display = "block";
    return;
  }

  const modal = createAuthModal();
  const input = document.getElementById("pw-input");
  const btn   = document.getElementById("pw-submit");
  const msg   = document.getElementById("pw-msg");

  input.focus();

  let busy = false;

  async function attempt() {
    if (busy) return;
    const val = input.value;

    if (!val || val.length === 0) { msg.textContent = "Please enter your password."; return; }
    if (val.length > MAX_PW_LENGTH) { msg.textContent = "Input too long."; return; }

    busy = true;
    btn.disabled = true;
    msg.textContent = "Verifying…";
    input.value = "";

    try {
      const currentLock = getLockState();
      if (currentLock.locked) { renderLocked(currentLock.until); return; }

      const derived = await deriveKey(val, CREDENTIAL.salt);

      if (timingSafeEqual(derived, CREDENTIAL.hash)) {
        clearAttempts();
        await issueToken();
        modal.remove();
        if (content) content.style.display = "block";
      } else {
        const tries   = recordFailedAttempt();
        const newLock = getLockState();
        if (newLock.locked) {
          renderLocked(newLock.until);
        } else {
          const left = MAX_ATTEMPTS - tries;
          msg.textContent = `❌ Wrong password. ${left} attempt${left !== 1 ? "s" : ""} remaining.`;
          busy = false;
          btn.disabled = false;
          input.focus();
        }
      }
    } catch (err) {
      msg.textContent = "An error occurred. Please try again.";
      busy = false;
      btn.disabled = false;
    }
  }

  btn.addEventListener("click", attempt);
  input.addEventListener("keydown", e => { if (e.key === "Enter") attempt(); });
}

// ================== CREDENTIAL GENERATOR (DEV ONLY) ==================
// Run generateCredential("yourpassword") in console, paste output into CREDENTIAL above.
// DELETE this function before going live.

async function generateCredential(password) {
  const salt    = randomHex(16);
  const derived = await deriveKey(password, salt);
  const cred    = { salt, hash: derived };
  console.log("Paste this into CREDENTIAL:\n", JSON.stringify(cred, null, 2));
  return cred;
}

// ================== INIT ==================
(function() {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startAuth);
  } else {
    startAuth();
  }
})();
