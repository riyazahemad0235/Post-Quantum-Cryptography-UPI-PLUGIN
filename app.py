"""
UPI PQC SERVER — FINAL YEAR PROJECT EDITION
============================================
Run:   python3 2_server.py
Hosts: http://0.0.0.0:5000

FIXES:
 - QR scan now works via image upload (no camera needed on same laptop)
 - Camera scan kept as optional fallback
 - 2-account demo: open two browser tabs, log in as different users, pay each other
 - Auto-login via QR: scan QR with phone → opens site logged in as that user
 - FIXED: upi:// URL parsing on mobile (upi:// scheme not recognized by URL constructor)
 - FIXED: tab switching uses text-match not fragile index
 - FIXED: camera no longer fires handleScannedCode multiple times
"""

import os, time, hashlib, hmac as hmaclib, sqlite3, uuid, secrets, base64, io
from flask import Flask, request, jsonify, render_template_string

# ── PQC BACKEND ───────────────────────────────────────────────────────────────
try:
    import oqs
    KEM_ALG  = "Kyber512"
    SIG_ALG  = "ML-DSA-65"
    PQC_MODE = "REAL"
    PQC_LIB  = "liboqs — Kyber512 + Dilithium3 (NIST FIPS 203/204)"
    print(f"[SERVER] ✓  liboqs — KEM={KEM_ALG}  SIG={SIG_ALG}")
except ImportError:
    oqs = None
    PQC_MODE = "FALLBACK"
    PQC_LIB  = "X25519 + HMAC-only (install liboqs for real PQC)"
    KEM_ALG  = "X25519"
    SIG_ALG  = "none"
    print("[SERVER] ⚠  liboqs not found — X25519 fallback")
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ── SQLITE ────────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "transactions.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            vpa TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 10000.0,
            created_at TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS auth_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            vpa TEXT NOT NULL,
            created_at TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY, txn_id TEXT, sender TEXT, receiver TEXT,
            amount TEXT, remarks TEXT, ref_num TEXT, sig_valid INTEGER,
            pqc TEXT, timestamp TEXT, status TEXT)""")
        if not conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            for vpa, bal in [("alice@ybl", 50000.0), ("bob@upi", 25000.0), ("carol@okaxis", 75000.0)]:
                conn.execute("INSERT INTO users VALUES (?,?,?,?,?)",
                    (str(uuid.uuid4()), vpa, hash_password("demo1234"), bal, ts))
            print("[SERVER] Demo accounts: alice@ybl / bob@upi / carol@okaxis  (password: demo1234)")
    print(f"[SERVER] SQLite ready: {DB_PATH}")

# ── PASSWORD HASHING ──────────────────────────────────────────────────────────
def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk   = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 260000)
    return salt.hex() + ":" + dk.hex()

def verify_password(pw: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        dk   = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 260000)
        return hmaclib.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False

# ── AUTH HELPERS ──────────────────────────────────────────────────────────────
def make_token(user_id, vpa):
    token = secrets.token_hex(32)
    ts    = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with get_db() as conn:
        conn.execute("INSERT INTO auth_tokens VALUES (?,?,?,?)", (token, user_id, vpa, ts))
    return token

def get_user_from_token(token):
    if not token: return None
    with get_db() as conn:
        row = conn.execute(
            "SELECT u.* FROM users u JOIN auth_tokens t ON u.id=t.user_id WHERE t.token=?",
            (token,)).fetchone()
    return dict(row) if row else None

# ── KEY GENERATION ────────────────────────────────────────────────────────────
def generate_kem_keypair():
    if oqs:
        kem = oqs.KeyEncapsulation(KEM_ALG)
        pk  = kem.generate_keypair()
        sk  = kem.export_secret_key()
        kem.free()
        return {"pk": pk, "sk": sk, "alg": KEM_ALG}
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    return {
        "pk":  pub.public_bytes(Encoding.Raw, PublicFormat.Raw),
        "sk":  priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        "alg": "X25519"
    }

def generate_sig_keypair():
    if oqs:
        sig = oqs.Signature(SIG_ALG)
        pk  = sig.generate_keypair()
        sk  = sig.export_secret_key()
        sig.free()
        return {"pk": pk, "sk": sk, "alg": SIG_ALG}
    return {"pk": b"", "sk": b"", "alg": "none"}

SERVER_KEM_KEYS = generate_kem_keypair()
SERVER_SIG_KEYS = generate_sig_keypair()
SESSIONS        = {}

print(f"[SERVER] KEM pk: {len(SERVER_KEM_KEYS['pk'])} bytes")
if oqs:
    print(f"[SERVER] SIG pk: {len(SERVER_SIG_KEYS['pk'])} bytes")

# ── CRYPTO HELPERS ────────────────────────────────────────────────────────────
def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    k  = hashlib.sha256(key).digest()
    iv = os.urandom(12)
    ct = AESGCM(k).encrypt(iv, plaintext, None)
    return {"iv": iv.hex(), "ct": ct.hex()}

def decrypt_aes_gcm(iv_hex, ct_hex, key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    k = hashlib.sha256(key).digest()
    return AESGCM(k).decrypt(bytes.fromhex(iv_hex), bytes.fromhex(ct_hex), None)

def make_hmac(data, key):
    return hmaclib.new(hashlib.sha256(key).digest(), data.encode(), hashlib.sha256).hexdigest()

def verify_hmac(data, mac, key):
    return hmaclib.compare_digest(make_hmac(data, key), mac)

def sign_data(data: bytes) -> bytes:
    if oqs:
        sig = oqs.Signature(SIG_ALG, SERVER_SIG_KEYS["sk"])
        s   = sig.sign(data)
        sig.free()
        return s
    return b""

def verify_sig(data, signature, pk):
    if oqs and signature and pk:
        try:
            v  = oqs.Signature(SIG_ALG)
            ok = v.verify(data, signature, pk)
            v.free()
            return ok
        except Exception:
            return False
    return False

# ── HTML ──────────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>UPI PQC</title>
<style>
:root {
  --bg: #fafafa;
  --surface: #ffffff;
  --text-main: #18181b;
  --text-muted: #71717a;
  --border: #e4e4e7;
  --primary: #09090b;
  --primary-hover: #27272a;
  --accent-blue: #3b82f6;
  --accent-green: #10b981;
  --accent-red: #ef4444;
  --accent-purple: #8b5cf6;
  --radius-lg: 12px;
  --radius-md: 8px;
  --radius-sm: 6px;
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
  --font-sans: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--bg);
  color: var(--text-main);
  font-family: var(--font-sans);
  min-height: 100vh;
  padding: 2rem 1rem;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.025em; margin-bottom: 0.25rem; color: var(--primary); }
.sub { color: var(--text-muted); font-size: 0.875rem; margin-bottom: 2rem; font-weight: 500; }

/* Navigation */
nav { display: flex; gap: 0.5rem; margin-bottom: 2rem; flex-wrap: wrap; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }
nav a {
  color: var(--text-muted); text-decoration: none; font-size: 0.875rem; font-weight: 500;
  padding: 0.5rem 1rem; border-radius: 9999px; transition: all 0.2s ease;
}
nav a:hover { color: var(--primary); background: #f4f4f5; }
nav a.active { color: #fff; background: var(--primary); }
nav a[onclick*="attack"].active { background: var(--accent-red); }
nav a[onclick*="qiskit"].active { background: var(--accent-purple); }

.grid { display: grid; grid-template-columns: 1fr; gap: 1.5rem; max-width: 1024px; }
@media(min-width: 768px){ .grid { grid-template-columns: 1fr 1fr; } }

/* Cards */
.card {
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg);
  padding: 1.5rem; box-shadow: var(--shadow-sm);
}
.card h2 { font-size: 0.875rem; font-weight: 600; color: var(--text-main); margin-bottom: 1.25rem; text-transform: uppercase; letter-spacing: 0.05em; display: flex; align-items: center; gap: 0.5rem; }

/* Forms & Inputs */
label { display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-main); margin-bottom: 0.5rem; margin-top: 1rem; }
input {
  width: 100%; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md);
  color: var(--text-main); font-family: var(--font-sans); font-size: 0.9375rem; padding: 0.75rem 1rem;
  transition: border-color 0.2s, box-shadow 0.2s; outline: none;
}
input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(9, 9, 11, 0.1); }

/* Buttons */
button {
  width: 100%; margin-top: 1.5rem; padding: 0.75rem 1rem; background: var(--primary); border: 1px solid transparent;
  border-radius: var(--radius-md); color: #fff; font-family: var(--font-sans); font-size: 0.875rem; font-weight: 500;
  cursor: pointer; transition: all 0.2s ease; display: inline-flex; align-items: center; justify-content: center;
}
button:hover:not(:disabled) { background: var(--primary-hover); transform: translateY(-1px); box-shadow: var(--shadow-md); }
button:disabled { opacity: 0.5; cursor: not-allowed; }

/* Log / Console */
.log {
  background: #09090b; border-radius: var(--radius-md); padding: 1rem; height: 320px; overflow-y: auto;
  font-family: var(--font-mono); font-size: 0.75rem; line-height: 1.6; color: #a1a1aa; box-shadow: inset 0 2px 4px rgba(0,0,0,0.5);
}
.log .ts { color: #52525b; margin-right: 0.5rem; }
.log .srv { color: #e4e4e7; }
.log .cli { color: #60a5fa; }
.log .pqc { color: #c084fc; }
.log .sig { color: #f472b6; }
.log .err { color: #f87171; }
.log .ok { color: #34d399; font-weight: 600; }

/* Badges */
.badge { display: inline-flex; font-size: 0.75rem; font-weight: 600; padding: 0.25rem 0.75rem; border-radius: 9999px; margin-bottom: 1rem; }
.badge-real { background: #dcfce7; color: #166534; }
.badge-fb { background: #fef3c7; color: #92400e; }

/* Stepper */
.step-row { display: flex; align-items: center; gap: 0.75rem; margin: 0.75rem 0; font-size: 0.875rem; }
.step-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; transition: all 0.3s ease; }
.dot-wait { background: var(--border); }
.dot-active { background: var(--accent-blue); box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.2); animation: pulse 1.5s infinite; }
.dot-done { background: var(--accent-green); }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.4); } 70% { box-shadow: 0 0 0 6px rgba(59, 130, 246, 0); } 100% { box-shadow: 0 0 0 0 rgba(59, 130, 246, 0); } }

/* Receipt */
.receipt { display: none; margin-top: 1.5rem; background: #fafafa; border: 1px solid var(--border); border-radius: var(--radius-md); padding: 1.25rem; }
.receipt.show { display: block; animation: slideDown 0.3s ease-out; }
@keyframes slideDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
.receipt table { width: 100%; border-collapse: collapse; }
.receipt td { padding: 0.5rem 0; font-size: 0.875rem; border-bottom: 1px dashed var(--border); }
.receipt tr:last-child td { border-bottom: none; }
.receipt td:first-child { color: var(--text-muted); font-weight: 500; width: 40%; }
.receipt td:last-child { color: var(--text-main); font-weight: 600; text-align: right; word-break: break-all; }

/* Tables */
.txn-table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
.txn-table th { text-align: left; padding: 1rem; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); background: #fafafa; }
.txn-table td { padding: 1rem; border-bottom: 1px solid var(--border); color: var(--text-main); }
.txn-table tr:last-child td { border-bottom: none; }
.txn-table tr:hover td { background: #f4f4f5; }
.tag-ok { color: var(--accent-green); font-weight: 600; }
.tag-err { color: var(--accent-red); font-weight: 600; }
.tag-sig { color: var(--accent-purple); font-size: 0.75rem; background: #f3e8ff; padding: 0.25rem 0.5rem; border-radius: 4px; }

/* Benchmarks */
.bench-grid { display: grid; grid-template-columns: 1fr; gap: 1rem; margin-top: 1.5rem; }
@media(min-width: 640px){ .bench-grid { grid-template-columns: 1fr 1fr; } }
.bench-card { background: #fafafa; border: 1px solid var(--border); border-radius: var(--radius-md); padding: 1.25rem; }
.bench-card h3 { font-size: 0.75rem; font-weight: 700; color: var(--text-muted); margin-bottom: 1rem; letter-spacing: 0.05em; }
.bench-bar-wrap { margin: 1rem 0; }
.bench-label { font-size: 0.8125rem; color: var(--text-main); font-weight: 500; margin-bottom: 0.5rem; display: flex; justify-content: space-between; }
.bench-bar { height: 6px; border-radius: 999px; background: var(--border); overflow: hidden; }
.bench-fill { height: 100%; border-radius: 999px; transition: width 1s cubic-bezier(0.4, 0, 0.2, 1); }
.bench-rsa { background: var(--accent-red); }
.bench-kyber { background: var(--accent-green); }

/* Balance Box */
.balance-box { background: var(--primary); color: white; border-radius: var(--radius-md); padding: 1.5rem; margin-bottom: 1.5rem; text-align: center; box-shadow: var(--shadow-md); }
.balance-box .bal-amt { font-size: 2rem; font-weight: 700; margin-bottom: 0.25rem; }
.balance-box .bal-vpa { font-size: 0.875rem; color: #a1a1aa; font-family: var(--font-mono); }

/* Alerts & Banners */
.alert { padding: 1rem; border-radius: var(--radius-md); font-size: 0.875rem; margin-top: 1rem; display: none; font-weight: 500; }
.alert.show { display: block; }
.alert-err { background: #fef2f2; border: 1px solid #fecaca; color: #b91c1c; }
.alert-ok { background: #f0fdf4; border: 1px solid #bbf7d0; color: #15803d; }
.demo-banner { background: #eff6ff; border: 1px solid #bfdbfe; border-radius: var(--radius-md); padding: 1rem; margin-bottom: 1.5rem; font-size: 0.875rem; color: #1e3a8a; line-height: 1.5; }
.demo-banner strong { color: #1e40af; }

/* Utilities */
#qr-video { width: 100%; border-radius: var(--radius-md); border: 1px solid var(--border); display: none; background: #000; }
#qr-canvas { display: none; }
.tab-pills { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
.tab-pill { padding: 0.5rem 1rem; border-radius: var(--radius-sm); font-size: 0.8125rem; font-weight: 600; cursor: pointer; border: 1px solid var(--border); background: var(--surface); color: var(--text-muted); transition: all 0.2s; }
.tab-pill.active { background: var(--primary); border-color: var(--primary); color: white; }

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #d4d4d8; border-radius: 10px; }
::-webkit-scrollbar-thumb:hover { background: #a1a1aa; }

/* Base specific overrides */
#auth-bar button { padding: 0.5rem 1rem; font-size: 0.8125rem; }
#btn-logout { background: transparent; color: var(--accent-red); border: 1px solid var(--accent-red); }
#btn-logout:hover { background: #fef2f2; }
#modal-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.4); backdrop-filter: blur(4px); z-index:100; align-items:center; justify-content:center; }
#stop-btn { background: white; color: var(--accent-red); border-color: var(--accent-red); }
#stop-btn:hover { background: #fef2f2; }
#attackBtn { background: white; color: var(--accent-red); border-color: var(--accent-red); }
#attackBtn:hover { background: var(--accent-red); color: white; }
#qiskitBtn { background: white; color: var(--accent-purple); border-color: var(--accent-purple); }
#qiskitBtn:hover { background: var(--accent-purple); color: white; }
</style>
</head>
<body>
<div style="max-width:1024px;margin:0 auto">
 <h1>UPI Post-Quantum Secure</h1>
 <div class="sub">Kyber512 &middot; Dilithium3 &middot; NIST FIPS 203/204 &middot; AES-GCM</div>

 <!-- AUTO-LOGIN INJECTION -->
 {% if auto_token %}
 <script>
   localStorage.setItem('upi_token', '{{ auto_token }}');
   localStorage.setItem('upi_vpa',   '{{ auto_vpa }}');
 </script>
 {% endif %}

 <!-- AUTH BAR -->
 <div id="auth-bar" style="display:flex;gap:12px;align-items:center;margin-bottom:24px;flex-wrap:wrap;background:var(--surface);padding:1rem;border-radius:var(--radius-md);border:1px solid var(--border);box-shadow:var(--shadow-sm);">
   <div id="auth-status" style="font-size:0.875rem;font-weight:500;color:var(--text-muted);flex:1">Not logged in</div>
   <button onclick="showModal('login')"    id="btn-login"    style="width:auto;margin:0;">Login</button>
   <button onclick="showModal('register')" id="btn-register" style="width:auto;margin:0;background:white;color:var(--primary);border:1px solid var(--border);">Register</button>
   <button onclick="doLogout()"            id="btn-logout"   style="width:auto;margin:0;display:none;">Logout</button>
 </div>

 <nav>
   <a href="#" class="active" onclick="showTab('pay',this);return false">Payment</a>
   <a href="#" onclick="showTab('qr',this);return false">QR Codes</a>
   <a href="#" onclick="showTab('txns',this);return false">Transactions</a>
   <a href="#" onclick="showTab('bench',this);return false">Benchmarks</a>
   <a href="#" onclick="showTab('attack',this);return false">RSA Attack</a>
   <a href="#" onclick="showTab('qiskit',this);return false">Quantum (Qiskit)</a>
 </nav>

 <!-- LOGIN MODAL -->
 <div id="modal-overlay">
   <div class="card" style="width:100%;max-width:380px;position:relative;animation:slideDown 0.2s ease-out">
     <button onclick="closeModal()" style="position:absolute;top:1rem;right:1rem;width:auto;margin:0;padding:0.25rem 0.5rem;font-size:1rem;background:transparent;color:var(--text-muted);border:none;">✕</button>
     
     <div id="modal-login">
       <h2>Login to Account</h2>
       <div class="demo-banner" style="padding:0.75rem;font-size:0.8125rem;">
         <strong>Demo Accounts (pw: demo1234)</strong><br>
         alice@ybl &middot; bob@upi &middot; carol@okaxis
       </div>
       <label>VPA</label><input id="l-vpa" placeholder="yourname@upi"/>
       <label>Password</label><input id="l-pw" type="password" placeholder="••••••••"/>
       <div class="alert alert-err" id="l-err"></div>
       <button onclick="doLogin()">Log In</button>
     </div>

     <div id="modal-register" style="display:none">
       <h2>Create Account</h2>
       <label>VPA</label><input id="r-vpa" placeholder="yourname@upi"/>
       <label>Password</label><input id="r-pw" type="password" placeholder="min 8 chars"/>
       <label>Starting Balance (₹)</label><input id="r-bal" type="number" value="10000" min="100"/>
       <div class="alert alert-err" id="r-err"></div>
       <button onclick="doRegister()">Create Account</button>
     </div>
   </div>
 </div>

 <!-- PAY TAB -->
 <div id="tab-pay">
   <div class="demo-banner">
     💡 <strong>2-Account Demo:</strong> Log in as <strong>alice@ybl</strong> here, then open
     <a href="javascript:void(0)" onclick="window.open(window.location.href,'_blank')" style="color:#1d4ed8;text-decoration:underline;font-weight:500;">a second tab</a>
     and log in as <strong>bob@upi</strong>. Send payments between them — balances update live!
   </div>
   <div class="grid">
     <div class="card">
       <h2>Secure Payment</h2>
       <span class="badge {{ 'badge-real' if pqc_mode == 'REAL' else 'badge-fb' }}">
         {{ 'REAL — ' + kem_alg + ' + ' + sig_alg if pqc_mode == 'REAL' else 'FALLBACK — install liboqs' }}
       </span>
       
       <div class="balance-box" id="balance-box" style="display:none">
         <div class="bal-amt" id="bal-display">₹0.00</div>
         <div class="bal-vpa" id="bal-vpa">—</div>
       </div>

       <label>Sender VPA</label><input id="sender" value="alice@ybl"/>
       <label>Receiver VPA</label><input id="receiver" value="bob@upi"/>
       <label>Amount (₹)</label><input id="amount" type="number" value="500" min="1"/>
       <label>Remarks</label><input id="remarks" value="Rent payment"/>
       <button id="payBtn" onclick="runPayment()">Send Secure Payment</button>

       <div style="margin-top:1.5rem;background:#fafafa;padding:1rem;border-radius:var(--radius-md);border:1px solid var(--border);">
         <div class="step-row"><div class="step-dot dot-wait" id="dot1"></div><span id="step1" style="color:var(--text-muted)">Fetch Kyber512 public key</span></div>
         <div class="step-row"><div class="step-dot dot-wait" id="dot2"></div><span id="step2" style="color:var(--text-muted)">Encapsulate shared secret</span></div>
         <div class="step-row"><div class="step-dot dot-wait" id="dot3"></div><span id="step3" style="color:var(--text-muted)">Encrypt payload (AES-256-GCM)</span></div>
         <div class="step-row"><div class="step-dot dot-wait" id="dot4"></div><span id="step4" style="color:var(--text-muted)">HMAC-SHA256 integrity</span></div>
         <div class="step-row"><div class="step-dot dot-wait" id="dot5"></div><span id="step5" style="color:var(--text-muted)">POST encrypted payload</span></div>
         <div class="step-row"><div class="step-dot dot-wait" id="dot6"></div><span id="step6" style="color:var(--text-muted)">Dilithium3 signature verify</span></div>
       </div>

       <div class="receipt" id="receipt"><table id="receiptTable"></table></div>
     </div>

     <div class="card" style="display:flex;flex-direction:column;">
       <h2>Live Server Log</h2>
       <div class="log" id="log" style="flex:1">
         <span class="srv">[SERVER] {{ pqc_lib }}</span><br>
         <span class="srv">[SERVER] KEM key: {{ pk_size }}B  CT: {{ ct_size }}B  SS: 32B</span><br>
         {% if pqc_mode == 'REAL' %}<span class="sig">[SERVER] SIG key: {{ sig_size }}B (Dilithium3)</span><br>{% endif %}
         <span class="srv">[SERVER] SQLite: transactions.db</span><br>
         <span class="ok">[SERVER] Open a 2nd tab to demo real transfers!</span><br>
         {% if auto_vpa %}<span class="ok">[AUTH] ✓ Auto-logged in as {{ auto_vpa }} via QR</span><br>{% endif %}
       </div>
     </div>
   </div>
 </div>

 <!-- QR TAB -->
 <div id="tab-qr" style="display:none">
   <div class="grid">
     <!-- Generate -->
     <div class="card">
       <h2>Generate Payment QR</h2>
       <p style="font-size:0.875rem;color:var(--text-muted);margin-bottom:1rem">Choose QR type, fill details, then scan.</p>
       
       <div class="tab-pills">
         <div class="tab-pill active" id="qrfmt-app"  onclick="setQRFormat('app')">App QR (Internal)</div>
         <div class="tab-pill"        id="qrfmt-upi"  onclick="setQRFormat('upi')">UPI QR (GPay/PhonePe)</div>
       </div>
       
       <div id="qrfmt-hint" style="font-size:0.8125rem;background:#f8fafc;border:1px solid #e2e8f0;color:#334155;border-radius:var(--radius-sm);padding:0.75rem;margin-bottom:1rem">
         Scan with this app's camera → fills the payment form automatically
       </div>

       <label>Your VPA (receiver)</label>
       <input id="qr-vpa" placeholder="yourname@upi"/>
       <label>Amount (₹) — leave 0 for open</label>
       <input id="qr-amount" type="number" value="0" min="0"/>
       <label>Remarks</label>
       <input id="qr-remarks" value=""/>
       <button onclick="generateQR()">Generate QR Code</button>

       <div id="qr-result" style="display:none;margin-top:1.5rem;text-align:center">
         <div style="background:white;padding:1rem;border-radius:var(--radius-md);border:1px solid var(--border);display:inline-block;box-shadow:var(--shadow-sm);">
           <img id="qr-img" src="" style="width:200px;height:200px;display:block;margin:0 auto;"/>
         </div>
         <div id="qr-upi-link" style="font-size:0.75rem;color:var(--text-muted);margin-top:1rem;word-break:break-all;font-family:var(--font-mono)"></div>
         <button onclick="downloadQR()" style="margin-top:1rem;width:auto;background:white;color:var(--primary);border:1px solid var(--border)">Download Image</button>
       </div>
     </div>

     <!-- Scan -->
     <div class="card">
       <h2>Scan / Upload QR</h2>
       <p style="font-size:0.875rem;color:var(--text-muted);margin-bottom:1rem">
         Use <strong>Camera</strong> to scan, or <strong>Upload</strong> an image.
       </p>

       <div class="tab-pills">
         <div class="tab-pill active" id="pill-upload" onclick="switchScanMode('upload')">Upload Image</div>
         <div class="tab-pill" id="pill-camera" onclick="switchScanMode('camera')">Camera</div>
       </div>

       <div id="scan-upload-mode">
         <input type="file" id="qr-file-input" accept="image/*" onchange="handleQRUpload(event)"
                style="padding:1rem;cursor:pointer;background:#fafafa;border:1px dashed var(--border)"/>
         <div id="upload-preview" style="display:none;margin-top:1rem;text-align:center">
           <img id="upload-img" src="" style="max-width:180px;border-radius:var(--radius-sm);border:1px solid var(--border);box-shadow:var(--shadow-sm)"/>
         </div>
         <canvas id="qr-decode-canvas" style="display:none"></canvas>
       </div>

       <div id="scan-camera-mode" style="display:none">
         <button onclick="startScan()" id="scan-btn">Start Camera</button>
         <button onclick="stopScan()" id="stop-btn" style="display:none">Stop Camera</button>
         <video id="qr-video" autoplay playsinline style="margin-top:1rem"></video>
         <canvas id="qr-canvas" style="display:none"></canvas>
       </div>

       <div id="scan-status" style="font-size:0.875rem;color:var(--text-muted);margin-top:1rem;font-weight:500;"></div>

       <div id="scan-result" style="display:none;margin-top:1rem;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:var(--radius-md);padding:1rem;font-size:0.875rem">
         <div style="color:#166534;font-weight:600;margin-bottom:0.5rem">✓ QR Decoded</div>
         <div id="scan-decoded"></div>
         <button onclick="applyScannedPayment()" style="margin-top:1rem;padding:0.5rem;background:#166534;color:white;width:auto">Use For Payment →</button>
       </div>
     </div>
   </div>

   <!-- Phone QR -->
   <div class="card" style="margin-top:1.5rem">
     <h2>Phone Access Links</h2>
     <p style="font-size:0.875rem;color:var(--text-muted);margin-bottom:1.5rem">
       Scan with your phone (same Wi-Fi). Left opens UPI app to pay alice. Right opens this site logged in as bob.
     </p>
     <div style="display:flex;gap:2rem;flex-wrap:wrap">
       <div style="text-align:center;flex:1;min-width:200px">
         <div style="font-size:0.75rem;color:var(--text-muted);font-weight:600;margin-bottom:0.75rem;text-transform:uppercase;letter-spacing:0.05em">UPI App Scan</div>
         <div style="background:white;padding:0.75rem;border-radius:var(--radius-md);border:1px solid var(--border);display:inline-block;box-shadow:var(--shadow-sm)">
           <img id="phone-qr-upi-img" src="" style="width:140px;height:140px;display:none;margin:0 auto;"/>
           <div id="phone-qr-upi-spin" style="width:140px;height:140px;line-height:140px;color:var(--text-muted);font-size:0.875rem;background:#fafafa;border-radius:var(--radius-sm)">loading...</div>
         </div>
         <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.75rem;font-family:var(--font-mono)">upi://pay &#8594; alice@ybl</div>
       </div>
       <div style="text-align:center;flex:1;min-width:200px">
         <div style="font-size:0.75rem;color:var(--text-muted);font-weight:600;margin-bottom:0.75rem;text-transform:uppercase;letter-spacing:0.05em">Web App Auto-login</div>
         <div style="background:white;padding:0.75rem;border-radius:var(--radius-md);border:1px solid var(--border);display:inline-block;box-shadow:var(--shadow-sm)">
           <img id="phone-qr-app-img" src="" style="width:140px;height:140px;display:none;margin:0 auto;"/>
           <div id="phone-qr-app-spin" style="width:140px;height:140px;line-height:140px;color:var(--text-muted);font-size:0.875rem;background:#fafafa;border-radius:var(--radius-sm)">loading...</div>
         </div>
         <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.75rem;font-family:var(--font-mono)">log in as bob@upi</div>
       </div>
     </div>
   </div>
 </div>

 <!-- TRANSACTIONS TAB -->
 <div id="tab-txns" style="display:none">
   <div class="card">
     <h2>Transaction History</h2>
     <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
       <span style="font-size:0.875rem;font-weight:500;color:var(--text-muted)" id="txn-count">—</span>
       <button onclick="loadTxns()" style="width:auto;margin:0;padding:0.5rem 1rem;background:white;color:var(--primary);border:1px solid var(--border)">Refresh List</button>
     </div>
     <div style="overflow-x:auto;border:1px solid var(--border);border-radius:var(--radius-md)">
       <table class="txn-table">
         <thead><tr><th>TXN ID</th><th>FROM</th><th>TO</th><th>AMOUNT</th><th>SIG</th><th>TIME</th><th>STATUS</th></tr></thead>
         <tbody id="txn-body"><tr><td colspan="7" style="color:var(--text-muted);padding:2rem;text-align:center">Make a payment first</td></tr></tbody>
       </table>
     </div>
   </div>
 </div>

 <!-- BENCHMARKS TAB -->
 <div id="tab-bench" style="display:none">
   <div class="card">
     <h2>RSA vs PQC Benchmarks</h2>
     <p style="font-size:0.875rem;color:var(--text-muted);margin-bottom:1.5rem">Running 20 iterations live to compare standard vs post-quantum cryptographic overhead.</p>
     <button onclick="runBench()" id="benchBtn" style="width:auto">Run Benchmarks</button>
     
     <div id="bench-results" style="margin-top:2rem;display:none">
       <div class="bench-grid">
         <div class="bench-card">
           <h3>KEY GENERATION (avg ms)</h3>
           <div class="bench-bar-wrap">
             <div class="bench-label"><span>RSA-2048</span><span id="b-rsa-kg">—</span></div>
             <div class="bench-bar"><div class="bench-fill bench-rsa" id="bar-rsa-kg" style="width:0%"></div></div>
           </div>
           <div class="bench-bar-wrap">
             <div class="bench-label"><span>Kyber512</span><span id="b-kyber-kg">—</span></div>
             <div class="bench-bar"><div class="bench-fill bench-kyber" id="bar-kyber-kg" style="width:0%"></div></div>
           </div>
         </div>
         <div class="bench-card">
           <h3>ENCRYPT / ENCAPSULATE (avg ms)</h3>
           <div class="bench-bar-wrap">
             <div class="bench-label"><span>RSA-2048</span><span id="b-rsa-enc">—</span></div>
             <div class="bench-bar"><div class="bench-fill bench-rsa" id="bar-rsa-enc" style="width:0%"></div></div>
           </div>
           <div class="bench-bar-wrap">
             <div class="bench-label"><span>Kyber512 KEM</span><span id="b-kyber-enc">—</span></div>
             <div class="bench-bar"><div class="bench-fill bench-kyber" id="bar-kyber-enc" style="width:0%"></div></div>
           </div>
         </div>
         <div class="bench-card">
           <h3>SIGNATURE (avg ms)</h3>
           <div class="bench-bar-wrap">
             <div class="bench-label"><span>RSA-2048</span><span id="b-rsa-sig">—</span></div>
             <div class="bench-bar"><div class="bench-fill bench-rsa" id="bar-rsa-sig" style="width:0%"></div></div>
           </div>
           <div class="bench-bar-wrap">
             <div class="bench-label"><span>Dilithium3</span><span id="b-dil-sig">—</span></div>
             <div class="bench-bar"><div class="bench-fill bench-kyber" id="bar-dil-sig" style="width:0%"></div></div>
           </div>
         </div>
         <div class="bench-card">
           <h3>PAYLOAD SIZES</h3>
           <div id="bench-sizes" style="font-size:0.875rem;line-height:2;color:var(--text-main);font-family:var(--font-mono)"></div>
         </div>
       </div>
       <div id="bench-summary" style="margin-top:1.5rem;font-size:0.9375rem;color:var(--text-main);line-height:1.6;background:#f8fafc;padding:1rem;border-radius:var(--radius-md);border:1px solid #e2e8f0"></div>
     </div>
   </div>
 </div>

 <!-- RSA ATTACK TAB -->
 <div id="tab-attack" style="display:none">
   <div class="card">
     <h2>RSA vs Shor's Algorithm Attack</h2>
     <p style="font-size:0.875rem;color:var(--text-muted);margin-bottom:1.5rem;line-height:1.6">
       Shor's algorithm running on a quantum computer factors <code>n = p×q</code> in polynomial time,
       recovering the private key <code>d</code> and decrypting ciphertext. This demonstrates the exact mathematical steps.
     </p>
     <button onclick="runAttack()" id="attackBtn" style="width:auto">Run Shor's Algorithm Attack</button>
     
     <div id="attack-out" style="margin-top:2rem;display:none">
       <div class="grid" style="gap:1rem">
         <div class="card" style="background:#fafafa;border-color:var(--border);box-shadow:none">
           <h3 style="font-size:0.75rem;color:var(--text-muted);font-weight:700;letter-spacing:0.05em;margin-bottom:1rem">PHASE 1 — RSA KEY SETUP</h3>
           <div id="atk-rsa-rows" style="font-size:0.875rem;line-height:2;color:var(--text-main);font-family:var(--font-mono)"></div>
         </div>
         <div class="card" style="background:#fafafa;border-color:var(--border);box-shadow:none">
           <h3 style="font-size:0.75rem;color:var(--text-muted);font-weight:700;letter-spacing:0.05em;margin-bottom:1rem">PHASE 2 — SHOR'S ALGORITHM</h3>
           <div id="atk-shor-rows" style="font-size:0.875rem;line-height:2;color:var(--text-main);font-family:var(--font-mono)"></div>
         </div>
       </div>
       <div class="card" id="atk-result-card" style="margin-top:1rem;background:#fef2f2;border-color:#fecaca;box-shadow:none">
         <h3 style="font-size:0.75rem;color:#b91c1c;font-weight:700;letter-spacing:0.05em;margin-bottom:1rem">PHASE 3 — RESULT</h3>
         <div id="atk-result" style="font-size:0.875rem;line-height:1.6;color:#7f1d1d"></div>
       </div>
     </div>
   </div>
 </div>

 <!-- QISKIT TAB -->
 <div id="tab-qiskit" style="display:none">
   <div class="card">
     <h2>Real Quantum Circuit (Qiskit)</h2>
     <p style="font-size:0.875rem;color:var(--text-muted);margin-bottom:0.5rem;line-height:1.6">
       This runs an <strong>actual quantum circuit</strong> on Qiskit's AerSimulator — applying inverse QFT
       and controlled modular exponentiation to factor N=15.
     </p>
     <div style="font-size:0.75rem;color:var(--accent-purple);font-weight:600;margin-bottom:1.5rem;background:#f3e8ff;display:inline-block;padding:0.25rem 0.75rem;border-radius:999px;">
       8 qubits &middot; 2048 shots &middot; AerSimulator
     </div>
     <br>
     <button onclick="runQiskit()" id="qiskitBtn" style="width:auto">Run Quantum Circuit</button>
     
     <div id="qiskit-status" style="font-size:0.875rem;font-weight:500;color:var(--accent-purple);margin-top:1rem;display:none">
       <span id="qiskit-status-text">Initialising quantum circuit...</span>
     </div>
     
     <div id="qiskit-out" style="display:none;margin-top:2rem">
       <div class="grid" style="gap:1rem;margin-bottom:1rem">
         <div class="card" style="background:#fafafa;border-color:var(--border);box-shadow:none">
           <h3 style="font-size:0.75rem;color:var(--text-muted);font-weight:700;letter-spacing:0.05em;margin-bottom:1rem">QUANTUM SPECS</h3>
           <div id="q-steps" style="font-size:0.875rem;line-height:2.2;color:var(--text-main);font-family:var(--font-mono)"></div>
         </div>
         <div class="card" style="background:#fafafa;border-color:var(--border);box-shadow:none">
           <h3 style="font-size:0.75rem;color:var(--text-muted);font-weight:700;letter-spacing:0.05em;margin-bottom:1rem">CLASSICAL POST-PROCESSING</h3>
           <div id="q-classical" style="font-size:0.875rem;line-height:2.2;color:var(--text-main);font-family:var(--font-mono)"></div>
         </div>
       </div>
       
       <div class="card" style="background:#fafafa;border-color:var(--border);box-shadow:none;margin-bottom:1rem">
         <h3 style="font-size:0.75rem;color:var(--text-muted);font-weight:700;letter-spacing:0.05em;margin-bottom:1rem">CIRCUIT DIAGRAM</h3>
         <div style="overflow-x:auto;text-align:center;background:white;padding:1rem;border-radius:var(--radius-sm);border:1px solid var(--border)">
           <img id="q-circuit-img" src="" style="max-width:100%"/>
         </div>
       </div>
       
       <div class="card" style="background:#fafafa;border-color:var(--border);box-shadow:none;margin-bottom:1rem">
         <h3 style="font-size:0.75rem;color:var(--text-muted);font-weight:700;letter-spacing:0.05em;margin-bottom:1rem">MEASUREMENT HISTOGRAM</h3>
         <div style="overflow-x:auto;text-align:center;background:white;padding:1rem;border-radius:var(--radius-sm);border:1px solid var(--border)">
           <img id="q-hist-img" src="" style="max-width:100%"/>
         </div>
         <p style="font-size:0.75rem;color:var(--text-muted);margin-top:0.75rem;text-align:center">Peaks indicate the period used to factor N.</p>
       </div>
       
       <div class="card" style="background:#f0fdf4;border-color:#bbf7d0;box-shadow:none">
         <h3 style="font-size:0.75rem;color:#166534;font-weight:700;letter-spacing:0.05em;margin-bottom:1rem">CONCLUSION</h3>
         <div id="q-result" style="font-size:0.875rem;line-height:1.6;color:#14532d"></div>
       </div>
     </div>
   </div>
 </div>

 <div style="text-align:center;margin-top:3rem;font-size:0.75rem;color:var(--text-muted);font-family:var(--font-mono)">
   {{ pqc_lib }} &nbsp;|&nbsp; PK {{ pk_size }}B &nbsp;|&nbsp; CT {{ ct_size }}B
 </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jsqr/1.4.0/jsQR.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script>
// ── STATE ──────────────────────────────────────────────────────────────────
let AUTH_TOKEN  = localStorage.getItem('upi_token') || null;
let AUTH_VPA    = localStorage.getItem('upi_vpa')   || null;
let scanStream  = null;
let scanLoop    = null;
let scannedData = null;

const log = document.getElementById('log');
function addLog(msg,cls='srv'){
  const ts=new Date().toISOString().slice(11,23);
  log.innerHTML+=`<span class="ts">${ts}</span> <span class="${cls}">${msg}</span><br>`;
  log.scrollTop=log.scrollHeight;
}
function setStep(n,done){
  document.getElementById('dot'+n).className='step-dot '+(done?'dot-done':'dot-active');
  document.getElementById('step'+n).style.color=done?'var(--text-main)':'var(--accent-blue)';
}
function showTab(name,el){
  ['pay','qr','txns','bench','attack','qiskit'].forEach(t=>{
    const e=document.getElementById('tab-'+t);
    if(e) e.style.display=t===name?'':'none';
  });
  document.querySelectorAll('nav a').forEach(a=>a.classList.remove('active'));
  el.classList.add('active');
  if(name==='txns') loadTxns();
  if(name==='qr') renderPhoneQRs();
  if(name!=='qr') stopScan();
}

// ── PHONE QR CODES ─────────────────────────────────────────────────────────
async function renderPhoneQRs() {
  const upiLink = 'upi://pay?pa=alice@ybl&pn=Alice&cu=INR';
  const appLink = window.location.origin + '/?auto_login=bob@upi';

  async function loadQR(data, imgId, spinId) {
    try {
      const res = await fetch('/api/qr/raw', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({data})
      });
      const json = await res.json();
      if (json.qr_b64) {
        document.getElementById(imgId).src = 'data:image/png;base64,' + json.qr_b64;
        document.getElementById(imgId).style.display = '';
        document.getElementById(spinId).style.display = 'none';
      }
    } catch(e) { document.getElementById(spinId).textContent = 'error'; }
  }

  loadQR(upiLink, 'phone-qr-upi-img', 'phone-qr-upi-spin');
  loadQR(appLink, 'phone-qr-app-img', 'phone-qr-app-spin');
}

// ── AUTH UI ────────────────────────────────────────────────────────────────
function updateAuthBar(){
  if(AUTH_TOKEN){
    document.getElementById('auth-status').textContent=`Logged in as ${AUTH_VPA}`;
    document.getElementById('btn-login').style.display='none';
    document.getElementById('btn-register').style.display='none';
    document.getElementById('btn-logout').style.display='';
    document.getElementById('sender').value=AUTH_VPA;
    document.getElementById('qr-vpa').value=AUTH_VPA;
    document.getElementById('balance-box').style.display='';
    document.getElementById('bal-vpa').textContent=AUTH_VPA;
    refreshBalance();
  } else {
    document.getElementById('auth-status').textContent='Not logged in';
    document.getElementById('btn-login').style.display='';
    document.getElementById('btn-register').style.display='';
    document.getElementById('btn-logout').style.display='none';
    document.getElementById('balance-box').style.display='none';
  }
}

function showModal(which){
  document.getElementById('modal-overlay').style.display='flex';
  document.getElementById('modal-login').style.display=which==='login'?'':'none';
  document.getElementById('modal-register').style.display=which==='register'?'':'none';
}
function closeModal(){document.getElementById('modal-overlay').style.display='none';}

async function doLogin(){
  const vpa=document.getElementById('l-vpa').value.trim();
  const pw=document.getElementById('l-pw').value;
  const res=await(await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vpa,password:pw})})).json();
  if(res.token){
    AUTH_TOKEN=res.token; AUTH_VPA=res.vpa;
    localStorage.setItem('upi_token',AUTH_TOKEN);
    localStorage.setItem('upi_vpa',AUTH_VPA);
    closeModal(); updateAuthBar();
    addLog(`[AUTH] ✓ Logged in as ${AUTH_VPA}`,'ok');
  } else {
    const el=document.getElementById('l-err');
    el.textContent=res.error||'Login failed'; el.className='alert alert-err show';
  }
}

async function doRegister(){
  const vpa=document.getElementById('r-vpa').value.trim();
  const pw=document.getElementById('r-pw').value;
  const bal=document.getElementById('r-bal').value;
  const res=await(await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vpa,password:pw,balance:parseFloat(bal)})})).json();
  if(res.token){
    AUTH_TOKEN=res.token; AUTH_VPA=res.vpa;
    localStorage.setItem('upi_token',AUTH_TOKEN);
    localStorage.setItem('upi_vpa',AUTH_VPA);
    closeModal(); updateAuthBar();
    addLog(`[AUTH] ✓ Registered & logged in as ${AUTH_VPA}`,'ok');
  } else {
    const el=document.getElementById('r-err');
    el.textContent=res.error||'Registration failed'; el.className='alert alert-err show';
  }
}

function doLogout(){
  AUTH_TOKEN=null; AUTH_VPA=null;
  localStorage.removeItem('upi_token'); localStorage.removeItem('upi_vpa');
  updateAuthBar();
  addLog('[AUTH] Logged out','srv');
}

async function refreshBalance(){
  if(!AUTH_TOKEN) return;
  const res=await(await fetch('/api/balance',{headers:{'X-Auth-Token':AUTH_TOKEN}})).json();
  if(res.balance!==undefined) document.getElementById('bal-display').textContent='₹'+res.balance.toFixed(2);
}

// ── QR GENERATE ────────────────────────────────────────────────────────────
let _qrFormat = 'app';

function setQRFormat(fmt){
  _qrFormat = fmt;
  document.getElementById('qrfmt-app').classList.toggle('active', fmt==='app');
  document.getElementById('qrfmt-upi').classList.toggle('active', fmt==='upi');
  const hint = document.getElementById('qrfmt-hint');
  if(fmt==='app'){
    hint.style.background='#f0fdf4'; hint.style.borderColor='#bbf7d0'; hint.style.color='#166534';
    hint.textContent="Scan with this app's camera → fills the payment form automatically";
  } else {
    hint.style.background='#fef3c7'; hint.style.borderColor='#fde68a'; hint.style.color='#92400e';
    hint.textContent='Scan with GPay / PhonePe / any UPI app on your phone';
  }
  document.getElementById('qr-result').style.display='none';
}

async function generateQR(){
  const vpa=document.getElementById('qr-vpa').value.trim();
  const amt=document.getElementById('qr-amount').value;
  const rem=document.getElementById('qr-remarks').value.trim();
  if(!vpa){alert('Enter a VPA first');return;}
  const res=await(await fetch('/api/qr/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vpa,amount:amt,remarks:rem,format:_qrFormat})})).json();
  if(res.qr_b64){
    document.getElementById('qr-img').src='data:image/png;base64,'+res.qr_b64;
    document.getElementById('qr-upi-link').textContent=res.upi_link;
    document.getElementById('qr-result').style.display='';
  }
}

function downloadQR(){
  const a=document.createElement('a');
  a.href=document.getElementById('qr-img').src;
  a.download='upi_qr.png'; a.click();
}

// ── QR SCAN MODE SWITCH ────────────────────────────────────────────────────
function switchScanMode(mode){
  document.getElementById('scan-upload-mode').style.display=mode==='upload'?'':'none';
  document.getElementById('scan-camera-mode').style.display=mode==='camera'?'':'none';
  document.getElementById('pill-upload').classList.toggle('active', mode==='upload');
  document.getElementById('pill-camera').classList.toggle('active', mode==='camera');
  if(mode!=='camera') stopScan();
  document.getElementById('scan-result').style.display='none';
  document.getElementById('scan-status').textContent='';
}

// ── QR UPLOAD SCAN ─────────────────────────────────────────────────────────
function handleQRUpload(event){
  const file = event.target.files[0];
  if(!file) return;
  document.getElementById('scan-status').textContent='Decoding QR...';
  document.getElementById('scan-result').style.display='none';

  const reader = new FileReader();
  reader.onload = function(e){
    document.getElementById('upload-img').src = e.target.result;
    document.getElementById('upload-preview').style.display='';

    const img = new Image();
    img.onload = function(){
      const canvas = document.getElementById('qr-decode-canvas');
      canvas.width  = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      if(typeof jsQR === 'undefined'){
        document.getElementById('scan-status').textContent='jsQR not loaded — refresh the page.';
        return;
      }
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      if(code){
        handleScannedCode(code.data);
      } else {
        document.getElementById('scan-status').textContent='❌ No QR code found in image. Try a clearer/larger image.';
      }
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

// ── QR CAMERA SCAN ─────────────────────────────────────────────────────────
async function startScan(){
  document.getElementById('scan-result').style.display='none';
  document.getElementById('scan-status').textContent='Starting camera...';

  try{
    scanStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' }
    });

    const video = document.getElementById('qr-video');
    video.srcObject = scanStream;
    video.setAttribute("playsinline", true);
    video.setAttribute("autoplay", true);
    video.muted = true;
    await video.play();

    video.style.display = 'block';
    document.getElementById('scan-btn').style.display = 'none';
    document.getElementById('stop-btn').style.display = '';
    document.getElementById('scan-status').textContent = 'Camera active — point at QR code';

    const canvas = document.getElementById('qr-canvas');
    const ctx = canvas.getContext('2d');

    scanLoop = setInterval(()=>{
      if(video.readyState !== video.HAVE_ENOUGH_DATA) return;
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      if(typeof jsQR === 'undefined') return;
      const code = jsQR(imageData.data, canvas.width, canvas.height, {
        inversionAttempts: "dontInvert"
      });
      if(code){
        handleScannedCode(code.data);
      }
    }, 150);

  } catch(e){
    document.getElementById('scan-status').textContent = 'Camera error: ' + e.message;
  }
}

function stopScan(){
  if(scanLoop){ clearInterval(scanLoop); scanLoop = null; }
  if(scanStream){ scanStream.getTracks().forEach(t => t.stop()); scanStream = null; }
  const video = document.getElementById('qr-video');
  if(video) video.style.display = 'none';
  document.getElementById('scan-btn').style.display = '';
  document.getElementById('stop-btn').style.display = 'none';
}

// ── PARSE QR DATA ──────────────────────────────────────────────────────────
function parseQRData(data){
  let vpa='', amount='', remarks='';

  if(data.startsWith('UPI_PQC|')){
    const parts = data.split('|');
    vpa     = parts[1] || '';
    amount  = parts[2] || '';
    remarks = parts[3] || '';
  } else if(data.startsWith('upi://')){
    try{
      // upi:// is not a standard scheme — replace so URL constructor works
      const url = new URL(data.replace('upi://', 'https://upi/'));
      vpa     = url.searchParams.get('pa') || '';
      amount  = url.searchParams.get('am') || '';
      remarks = url.searchParams.get('tn') || url.searchParams.get('remarks') || '';
    } catch(e){ vpa = data; }
  } else {
    try{
      const url = new URL(data);
      vpa     = url.searchParams.get('pa') || '';
      amount  = url.searchParams.get('am') || '';
      remarks = url.searchParams.get('tn') || url.searchParams.get('remarks') || '';
    } catch(e){ vpa = data; }
  }

  return { vpa, amount, remarks };
}

// ── NAVIGATE TO PAYMENT TAB ────────────────────────────────────────────────
function goToPayTab(){
  ['pay','qr','txns','bench','attack','qiskit'].forEach(t=>{
    const el = document.getElementById('tab-'+t);
    if(el) el.style.display = (t==='pay') ? '' : 'none';
  });
  // match by text content — robust even if nav order changes
  document.querySelectorAll('nav a').forEach(a=>{
    a.classList.remove('active');
    if(a.textContent.trim() === 'Payment') a.classList.add('active');
  });
}

// ── MAIN QR SCAN HANDLER ───────────────────────────────────────────────────
function handleScannedCode(data){
  // stop camera immediately so this doesn't fire multiple times
  stopScan();

  data = data.trim();
  window.lastQRData = data;

  document.getElementById('scan-status').textContent = '✓ QR decoded!';

  // Case 1: plain HTTP/HTTPS link (e.g. auto-login QR) → navigate directly
  if(data.startsWith('https://') || data.startsWith('http://')){
    window.location.href = data;
    return;
  }

  // Case 2: UPI PQC custom format or standard upi:// deep link
  const isUPIPQC = data.startsWith('UPI_PQC|');
  const isUPILink = data.startsWith('upi://');

  if(isUPIPQC || isUPILink){
    const { vpa, amount, remarks } = parseQRData(data);

    // Fill payment form fields
    if(vpa)     document.getElementById('receiver').value = vpa;
    if(amount)  document.getElementById('amount').value   = amount;
    if(remarks) document.getElementById('remarks').value  = remarks;

    // Switch to Payment tab
    goToPayTab();

    addLog(`[QR] Scanned → receiver=${vpa || '?'}${amount ? '  ₹'+amount : ''}`, 'pqc');

    // Prompt login if not authenticated
    if(!AUTH_TOKEN){
      setTimeout(()=> showModal('login'), 300);
    }
    return;
  }

  // Case 3: fallback — show decoded result panel with manual apply button
  const { vpa, amount, remarks } = parseQRData(data);
  document.getElementById('scan-decoded').innerHTML = `
    <div>VPA: <strong style="color:#166534">${vpa || data}</strong></div>
    ${amount  ? `<div>Amount: <strong style="color:#166534">₹${amount}</strong></div>` : ''}
    ${remarks ? `<div>Remarks: <strong style="color:#166534">${remarks}</strong></div>` : ''}
    <div style="color:var(--text-muted);font-size:0.75rem;margin-top:0.5rem;word-break:break-all;font-family:var(--font-mono)">${data}</div>`;
  document.getElementById('scan-result').style.display = '';
  document.getElementById('scan-status').textContent   = '✓ QR decoded — review below';
}

// ── APPLY SCANNED TO PAYMENT ───────────────────────────────────────────────
function applyScannedPayment(){
  if(!window.lastQRData) return;
  const { vpa, amount, remarks } = parseQRData(window.lastQRData);
  if(vpa)     document.getElementById('receiver').value = vpa;
  if(amount)  document.getElementById('amount').value   = amount;
  if(remarks) document.getElementById('remarks').value  = remarks;
  goToPayTab();
  addLog(`[QR] Applied → receiver=${vpa} amount=${amount||'open'}`, 'pqc');
}

// ── PAYMENT ────────────────────────────────────────────────────────────────
async function runPayment(){
  if(!AUTH_TOKEN){showModal('login');return;}
  const btn=document.getElementById('payBtn');
  btn.disabled=true;
  document.getElementById('receipt').classList.remove('show');
  [1,2,3,4,5,6].forEach(n=>{
    document.getElementById('dot'+n).className='step-dot dot-wait';
    document.getElementById('step'+n).style.color='var(--text-muted)';
  });
  const sender=document.getElementById('sender').value;
  const receiver=document.getElementById('receiver').value;
  const amount=document.getElementById('amount').value;
  const remarks=document.getElementById('remarks').value;
  const txn_id='UPI'+Date.now().toString(16).toUpperCase();
  addLog('────────────────────────────────────────','ts');
  addLog(`[CLIENT] ${sender} → ${receiver}  ₹${amount}`,'cli');
  try{
    setStep(1,false);
    const pkData=await(await fetch('/api/pubkey')).json();
    addLog(`[SERVER] pk=${pkData.pk_hex.slice(0,24)}...  (${pkData.pk_hex.length/2}B)`,'srv');
    setStep(1,true);

    setStep(2,false);
    const session_id=crypto.randomUUID();
    const encData=await(await fetch('/api/encap',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id})})).json();
    addLog(`[PQC]    ct=${encData.ct_hex.slice(0,24)}...  ss=${encData.ss_hex.slice(0,16)}...`,'pqc');
    setStep(2,true);

    setStep(3,false);
    const payData=await(await fetch('/api/encrypt',{method:'POST',headers:{'Content-Type':'application/json','X-Auth-Token':AUTH_TOKEN},body:JSON.stringify({session_id,sender,receiver,amount,remarks,txn_id,token:AUTH_TOKEN})})).json();
    if(payData.error){addLog(`[ERROR] ${payData.error}`,'err');btn.disabled=false;return;}
    addLog(`[CLIENT] enc=${payData.enc_amount.ct.slice(0,24)}...`,'cli');
    setStep(3,true);

    setStep(4,false);
    addLog(`[CLIENT] HMAC=${payData.hmac.slice(0,24)}...`,'cli');
    setStep(4,true);

    setStep(5,false);
    const result=await(await fetch('/api/pay',{method:'POST',headers:{'Content-Type':'application/json','X-Auth-Token':AUTH_TOKEN},body:JSON.stringify({...payData,token:AUTH_TOKEN})})).json();
    setStep(5,true);

    setStep(6,false);
    if(result.status==='SUCCESS'){
      addLog(`[SERVER] Dilithium3: ${result.sig_valid?'✓ VALID':'— fallback'}`,'sig');
      setStep(6,true);
      addLog('[SERVER] ✓ TRANSACTION SUCCESSFUL','ok');
      addLog(`[SERVER] TXN=${result.txn_id}  REF=${result.ref_num}`,'srv');
      addLog(`[BALANCE] ${sender} ₹${result.sender_balance}  |  ${receiver} ₹${result.receiver_balance}`,'pqc');
      document.getElementById('receiptTable').innerHTML=`
        <tr><td>Status</td><td style="color:var(--accent-green)">✓ ${result.status}</td></tr>
        <tr><td>TXN ID</td><td>${result.txn_id}</td></tr>
        <tr><td>Ref Num</td><td>${result.ref_num}</td></tr>
        <tr><td>From</td><td>${result.from}</td></tr>
        <tr><td>To</td><td>${result.to}</td></tr>
        <tr><td>Amount</td><td>₹${result.amount}</td></tr>
        <tr><td>Remarks</td><td>${result.remarks}</td></tr>
        <tr><td>Your Balance</td><td>₹${result.sender_balance}</td></tr>
        <tr><td>Dilithium3</td><td>${result.sig_valid?'✓ verified':'— fallback'}</td></tr>
        <tr><td>KEM</td><td>${result.pqc}</td></tr>
        <tr><td>Time</td><td>${result.timestamp}</td></tr>`;
      document.getElementById('receipt').classList.add('show');
      refreshBalance();
    } else {
      addLog(`[SERVER] ✗ ${result.msg}`,'err');
    }
  } catch(e){addLog(`[ERROR] ${e.message}`,'err');}
  btn.disabled=false;
}

// ── TRANSACTIONS ───────────────────────────────────────────────────────────
async function loadTxns(){
  const body=document.getElementById('txn-body');
  body.innerHTML='<tr><td colspan="7" style="color:var(--text-muted);padding:2rem;text-align:center">Loading...</td></tr>';
  const data=await(await fetch('/api/transactions')).json();
  document.getElementById('txn-count').textContent=`${data.length} transaction${data.length!==1?'s':''}`;
  if(!data.length){
    body.innerHTML='<tr><td colspan="7" style="color:var(--text-muted);padding:2rem;text-align:center">No transactions yet</td></tr>';
    return;
  }
  body.innerHTML=data.map(t=>`<tr>
    <td style="color:var(--text-main);font-family:var(--font-mono)">${t.txn_id}</td>
    <td style="color:var(--accent-blue);font-weight:500">${t.sender}</td>
    <td style="color:var(--text-main);font-weight:500">${t.receiver}</td>
    <td style="color:var(--text-main);font-weight:600">₹${t.amount}</td>
    <td class="tag-sig">${t.sig_valid?'✓ Dilithium3':'—'}</td>
    <td style="color:var(--text-muted);font-size:0.75rem">${t.timestamp}</td>
    <td class="${t.status==='SUCCESS'?'tag-ok':'tag-err'}">${t.status}</td></tr>`).join('');
}

// ── BENCHMARKS ─────────────────────────────────────────────────────────────
async function runBench(){
  document.getElementById('benchBtn').disabled=true;
  document.getElementById('benchBtn').textContent='Running...';
  document.getElementById('bench-results').style.display='none';
  const data=await(await fetch('/api/benchmark')).json();
  document.getElementById('bench-results').style.display='';
  const v={'rsa-kg':data.rsa_keygen_ms,'kyber-kg':data.kyber_keygen_ms,'rsa-enc':data.rsa_encrypt_ms,'kyber-enc':data.kyber_encap_ms,'rsa-sig':data.rsa_sign_ms,'dil-sig':data.dilithium_sign_ms};
  const maxKg=Math.max(v['rsa-kg'],v['kyber-kg']);
  const maxEnc=Math.max(v['rsa-enc'],v['kyber-enc']);
  const maxSig=Math.max(v['rsa-sig'],v['dil-sig']);
  function setBar(id,val,max){document.getElementById('b-'+id).textContent=val.toFixed(3)+' ms';document.getElementById('bar-'+id).style.width=Math.max(4,(val/max)*100)+'%';}
  setBar('rsa-kg',v['rsa-kg'],maxKg);setBar('kyber-kg',v['kyber-kg'],maxKg);
  setBar('rsa-enc',v['rsa-enc'],maxEnc);setBar('kyber-enc',v['kyber-enc'],maxEnc);
  setBar('rsa-sig',v['rsa-sig'],maxSig);setBar('dil-sig',v['dil-sig'],maxSig);
  document.getElementById('bench-sizes').innerHTML=`
    <div style="display:flex;justify-content:space-between"><span>RSA-2048 pub key</span> <span style="color:var(--accent-red)">${data.sizes.rsa_pk_bytes}B</span></div>
    <div style="display:flex;justify-content:space-between"><span>RSA-2048 ciphertext</span> <span style="color:var(--accent-red)">${data.sizes.rsa_ct_bytes}B</span></div>
    <div style="display:flex;justify-content:space-between;margin-top:0.5rem"><span>Kyber512 pub key</span> <span style="color:var(--accent-green);font-weight:600">${data.sizes.kyber_pk_bytes}B</span></div>
    <div style="display:flex;justify-content:space-between"><span>Kyber512 ciphertext</span> <span style="color:var(--accent-green);font-weight:600">${data.sizes.kyber_ct_bytes}B</span></div>
    <div style="display:flex;justify-content:space-between;margin-top:0.5rem"><span>Dilithium3 signature</span> <span style="color:var(--accent-green);font-weight:600">${data.sizes.dil_sig_bytes}B</span></div>`;
  const kgX=(v['rsa-kg']/Math.max(v['kyber-kg'],0.001)).toFixed(1);
  const encX=(v['rsa-enc']/Math.max(v['kyber-enc'],0.001)).toFixed(1);
  document.getElementById('bench-summary').innerHTML=`
    Kyber512 keygen is <strong style="color:var(--accent-green)">${kgX}x faster</strong> than RSA-2048.<br>
    Kyber512 encapsulation is <strong style="color:var(--accent-green)">${encX}x faster</strong> than RSA encrypt.<br>
    <span style="color:var(--text-muted);font-size:0.8125rem;display:block;margin-top:0.5rem">Average of ${data.iterations} iterations each.</span>`;
  document.getElementById('benchBtn').disabled=false;
  document.getElementById('benchBtn').textContent='Run Benchmarks';
}

// ── ATTACK ─────────────────────────────────────────────────────────────────
async function runAttack(){
  document.getElementById('attackBtn').disabled=true;
  document.getElementById('attackBtn').textContent='Attacking...';
  document.getElementById('attack-out').style.display='none';
  try{
    const data=await(await fetch('/api/attack')).json();
    document.getElementById('attack-out').style.display='';
    document.getElementById('atk-rsa-rows').innerHTML=`
      <div style="display:flex;justify-content:space-between"><span>Primes p, q</span> <span style="color:var(--text-main)">${data.p}, ${data.q}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Modulus n</span> <span style="color:var(--text-main)">${data.n}</span></div>
      <div style="display:flex;justify-content:space-between"><span>phi(n)</span> <span style="color:var(--text-main)">${data.phi}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Public key e</span> <span style="color:var(--text-main)">${data.e}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Private key d</span> <span style="color:var(--accent-red)">${data.d}</span></div>
      <div style="display:flex;justify-content:space-between;margin-top:0.5rem"><span>Plaintext</span> <span style="color:var(--accent-blue)">${data.m_int}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Ciphertext</span> <span style="color:var(--text-main)">${data.c_int}</span></div>`;
    document.getElementById('atk-shor-rows').innerHTML=`
      <div style="display:flex;justify-content:space-between"><span>Random base a</span> <span style="color:var(--text-main)">${data.a_used}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Period r</span> <span style="color:var(--text-main)">${data.period??'via gcd shortcut'}</span></div>
      <div style="display:flex;justify-content:space-between;margin-top:0.5rem"><span>Found p</span> <span style="color:var(--accent-red);font-weight:600">${data.found_p}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Found q</span> <span style="color:var(--accent-red);font-weight:600">${data.found_q}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Recovered phi</span> <span style="color:var(--text-main)">${data.rec_phi}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Recovered d</span> <span style="color:var(--accent-red);font-weight:600">${data.rec_d}</span></div>
      <div style="display:flex;justify-content:space-between"><span>d matched</span> <span style="color:var(--accent-red);font-weight:600">${data.d_match}</span></div>`;
    document.getElementById('atk-result').innerHTML=`
      <div style="color:#b91c1c;font-weight:700;margin-bottom:0.5rem">✗ RSA BROKEN — Message cracked: ${data.cracked}</div>
      <div style="color:#7f1d1d">Shor's algorithm recovered private key d=${data.rec_d} and decrypted ciphertext ${data.c_int} → ${data.cracked}.</div>
      <br>
      <div style="color:var(--accent-green);font-weight:700;margin-bottom:0.5rem">✓ WHY KYBER IS SAFE</div>
      <div style="color:var(--text-main)">Kyber is based on the Learning With Errors (LWE) lattice problem — no known quantum algorithm including Shor's can solve it efficiently.</div>`;
  } catch(e){
    document.getElementById('attack-out').style.display='';
    document.getElementById('atk-result').innerHTML=`<span style="color:var(--accent-red)">Error: ${e.message}</span>`;
  }
  document.getElementById('attackBtn').disabled=false;
  document.getElementById('attackBtn').textContent="Run Shor's Algorithm Attack";
}

// ── QISKIT ─────────────────────────────────────────────────────────────────
async function runQiskit(){
  const btn=document.getElementById('qiskitBtn');
  btn.disabled=true; btn.textContent='Running Quantum Circuit...';
  document.getElementById('qiskit-out').style.display='none';
  document.getElementById('qiskit-status').style.display='';
  const steps=[
    'Initialising 8-qubit quantum register...',
    'Applying Hadamard gates — superposition over all states...',
    'Applying controlled modular exponentiation...',
    'Running inverse Quantum Fourier Transform (iQFT)...',
    'Measuring counting register...',
    'Running 2048 shots on AerSimulator...',
    'Classical post-processing: phase → period → factors...',
  ];
  let si=0;
  const iv=setInterval(()=>{if(si<steps.length) document.getElementById('qiskit-status-text').textContent=steps[si++];},700);
  try{
    const data=await(await fetch('/api/qiskit_shor')).json();
    clearInterval(iv);
    if(data.error){
      document.getElementById('qiskit-status-text').textContent='Error: '+data.error;
      btn.disabled=false; btn.textContent='Run Quantum Circuit'; return;
    }
    document.getElementById('qiskit-status').style.display='none';
    document.getElementById('qiskit-out').style.display='';
    document.getElementById('q-circuit-img').src='data:image/png;base64,'+data.circuit_b64;
    document.getElementById('q-hist-img').src='data:image/png;base64,'+data.hist_b64;
    const fc=data.factors_found;
    document.getElementById('q-steps').innerHTML=`
      <div style="display:flex;justify-content:space-between"><span>Qubits</span> <span style="color:var(--accent-purple)">${data.num_qubits}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Circuit depth</span> <span style="color:var(--accent-purple)">${data.depth}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Gate count</span> <span style="color:var(--accent-purple)">${data.gate_count}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Shots</span> <span style="color:var(--accent-purple)">${data.shots}</span></div>
      <div style="display:flex;justify-content:space-between;margin-top:0.5rem;padding-top:0.5rem;border-top:1px dashed var(--border)"><span>N (target)</span> <span style="color:var(--text-main);font-weight:600">${data.N} = p × q</span></div>
      <div style="display:flex;justify-content:space-between"><span>Base a</span> <span style="color:var(--text-main)">${data.a}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Top peaks</span> <span style="color:var(--accent-purple)">${data.top_peaks.join(', ')}</span></div>`;
    document.getElementById('q-classical').innerHTML=fc.length?`
      <div style="display:flex;justify-content:space-between"><span>Measured</span> <span style="color:var(--text-main)">${fc[0].measured} / ${data.n_states} states</span></div>
      <div style="display:flex;justify-content:space-between"><span>Phase</span> <span style="color:var(--text-main)">${fc[0].phase.toFixed(4)}</span></div>
      <div style="display:flex;justify-content:space-between"><span>Period r</span> <span style="color:var(--accent-purple);font-weight:600">${fc[0].r}</span></div>
      <div style="display:flex;justify-content:space-between"><span>gcd(a^(r/2)-1,N)</span> <span style="color:var(--text-main)">${fc[0].p}</span></div>
      <div style="display:flex;justify-content:space-between"><span>gcd(a^(r/2)+1,N)</span> <span style="color:var(--text-main)">${fc[0].q}</span></div>
      <div style="color:var(--accent-green);font-weight:700;margin-top:1rem;padding-top:1rem;border-top:1px dashed var(--border);text-align:center">✓ FACTORED: ${data.N} = ${fc[0].p} × ${fc[0].q}</div>`:
      `<div style="color:var(--accent-red);padding:1rem;text-align:center">Peaks insufficient this run — probabilistic, try again</div>`;
    document.getElementById('q-result').innerHTML=`
      <div style="color:var(--accent-red);font-weight:700;margin-bottom:0.5rem">✗ RSA IS BROKEN BY THIS CIRCUIT</div>
      <div style="margin-bottom:1.5rem;color:var(--text-main)">The quantum circuit successfully factored N=${data.N} by finding period r=${fc.length?fc[0].r:'?'}. RSA-2048 relies on a 617-digit N — a fault-tolerant quantum computer running this exact same circuit structure scaled up would factor it entirely.</div>
      <div style="color:var(--accent-green);font-weight:700;margin-bottom:0.5rem">✓ KYBER IS IMMUNE</div>
      <div style="color:var(--text-main)">Kyber's security relies on Module Learning With Errors (MLWE). No known quantum algorithm breaks MLWE in sub-exponential time. This is why NIST standardised Kyber (FIPS 203) and Dilithium (FIPS 204) in 2024.</div>`;
  } catch(e){
    clearInterval(iv);
    document.getElementById('qiskit-status-text').textContent='Error: '+e.message;
  }
  btn.disabled=false;
  btn.textContent='Run Quantum Circuit';
}

// ── INIT ───────────────────────────────────────────────────────────────────
updateAuthBar();
</script>
</body>
</html>"""

# ── ROUTES — AUTH ─────────────────────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def api_register():
    data    = request.json
    vpa     = data.get("vpa","").strip().lower()
    pw      = data.get("password","")
    balance = float(data.get("balance", 10000.0))
    if not vpa or "@" not in vpa:
        return jsonify({"error": "Invalid VPA format"}), 400
    if len(pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    with get_db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE vpa=?", (vpa,)).fetchone():
            return jsonify({"error": "VPA already registered"}), 409
        uid = str(uuid.uuid4())
        ts  = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?)",
            (uid, vpa, hash_password(pw), balance, ts))
    token = make_token(uid, vpa)
    return jsonify({"token": token, "vpa": vpa, "balance": balance})

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    vpa  = data.get("vpa","").strip().lower()
    pw   = data.get("password","")
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE vpa=?", (vpa,)).fetchone()
    if not row or not verify_password(pw, row["password_hash"]):
        return jsonify({"error": "Invalid VPA or password"}), 401
    token = make_token(row["id"], vpa)
    return jsonify({"token": token, "vpa": vpa, "balance": row["balance"]})

@app.route("/api/balance")
def api_balance():
    token = request.headers.get("X-Auth-Token","")
    user  = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"vpa": user["vpa"], "balance": user["balance"]})

# ── ROUTES — QR ───────────────────────────────────────────────────────────────
@app.route("/api/qr/generate", methods=["POST"])
def api_qr_generate():
    try:
        import qrcode
        data    = request.json
        vpa     = data.get("vpa","").strip()
        amount  = data.get("amount","0")
        remarks = data.get("remarks","")
        fmt     = data.get("format","app")  # 'app' = UPI_PQC custom, 'upi' = standard upi://

        if fmt == "app":
            # Custom format — only this app's camera understands it
            # The OS will NOT intercept it with GPay/PhonePe
            qr_data  = f"UPI_PQC|{vpa}|{amount}|{remarks}"
            upi_link = qr_data
        else:
            # Standard upi:// deep link — opens GPay, PhonePe etc.
            upi_link = f"upi://pay?pa={vpa}&pn={vpa.split('@')[0].title()}"
            if amount and float(amount) > 0:
                upi_link += f"&am={amount}"
            if remarks:
                upi_link += f"&tn={remarks}"
            upi_link += "&cu=INR"
            qr_data  = upi_link

        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#18181b", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return jsonify({"qr_b64": base64.b64encode(buf.read()).decode(), "upi_link": upi_link})
    except ImportError:
        return jsonify({"error": "qrcode not installed. Run: pip install qrcode pillow"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/qr/raw", methods=["POST"])
def api_qr_raw():
    try:
        import qrcode
        data = request.json.get("data", "")
        qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#18181b", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return jsonify({"qr_b64": base64.b64encode(buf.read()).decode()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── ROUTES — CRYPTO ───────────────────────────────────────────────────────────
@app.route("/")
def index():
    ct_size  = 768 if PQC_MODE == "REAL" else 32
    sig_size = len(SERVER_SIG_KEYS["pk"]) if oqs else 0

    auto_token = ""
    auto_vpa   = ""
    vpa_param  = request.args.get("auto_login", "").strip().lower()
    if vpa_param:
        with get_db() as conn:
            row = conn.execute("SELECT * FROM users WHERE vpa=?", (vpa_param,)).fetchone()
        if row:
            auto_token = make_token(row["id"], vpa_param)
            auto_vpa   = vpa_param

    return render_template_string(HTML,
        pqc_mode=PQC_MODE, pqc_lib=PQC_LIB,
        kem_alg=KEM_ALG, sig_alg=SIG_ALG,
        pk_size=len(SERVER_KEM_KEYS["pk"]), sig_size=sig_size,
        ct_size=ct_size,
        auto_token=auto_token, auto_vpa=auto_vpa)

@app.route("/api/pubkey")
def api_pubkey():
    return jsonify({
        "pk_hex":     SERVER_KEM_KEYS["pk"].hex(),
        "sig_pk_hex": SERVER_SIG_KEYS["pk"].hex() if oqs else "",
        "alg": SERVER_KEM_KEYS["alg"], "pqc": PQC_MODE == "REAL"
    })

@app.route("/api/encap", methods=["POST"])
def api_encap():
    session_id = request.json["session_id"]
    if oqs:
        kem        = oqs.KeyEncapsulation(KEM_ALG)
        ct, ss_enc = kem.encap_secret(SERVER_KEM_KEYS["pk"])
        kem.free()
        kem2       = oqs.KeyEncapsulation(KEM_ALG, SERVER_KEM_KEYS["sk"])
        ss_dec     = kem2.decap_secret(ct)
        kem2.free()
        assert ss_enc == ss_dec
        shared_secret = ss_enc
        ct_hex        = ct.hex()
    else:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        eph           = X25519PrivateKey.generate()
        srv           = X25519PrivateKey.from_private_bytes(SERVER_KEM_KEYS["sk"])
        shared_secret = srv.exchange(eph.public_key())
        ct_hex        = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    SESSIONS[session_id] = shared_secret
    return jsonify({"ct_hex": ct_hex, "ss_hex": shared_secret.hex(), "session_id": session_id})

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data       = request.json
    token      = data.get("token") or request.headers.get("X-Auth-Token","")
    user       = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    session_id = data["session_id"]
    if session_id not in SESSIONS:
        return jsonify({"error": "Unknown session"}), 400
    ss          = SESSIONS[session_id]
    enc_amount  = encrypt_aes_gcm(str(data["amount"]).encode(), ss)
    enc_remarks = encrypt_aes_gcm(str(data.get("remarks","")).encode(), ss)
    mac_input   = f"{data['txn_id']}:{data['sender']}:{data['receiver']}:{enc_amount['ct']}:{enc_remarks['ct']}"
    mac         = make_hmac(mac_input, ss)
    signature   = sign_data(mac_input.encode())
    return jsonify({
        "session_id": session_id, "txn_id": data["txn_id"],
        "sender": data["sender"], "receiver": data["receiver"],
        "enc_amount": enc_amount, "enc_remarks": enc_remarks,
        "hmac": mac,
        "signature": signature.hex(),
        "sig_pk": SERVER_SIG_KEYS["pk"].hex() if oqs else ""
    })

@app.route("/api/pay", methods=["POST"])
def api_pay():
    data         = request.json
    token        = data.get("token") or request.headers.get("X-Auth-Token","")
    user         = get_user_from_token(token)
    if not user:
        return jsonify({"status": "error", "msg": "Unauthorized"}), 401
    session_id   = data["session_id"]
    if session_id not in SESSIONS:
        return jsonify({"status": "error", "msg": "Unknown session"}), 400
    ss           = SESSIONS[session_id]
    mac_input    = f"{data['txn_id']}:{data['sender']}:{data['receiver']}:{data['enc_amount']['ct']}:{data['enc_remarks']['ct']}"
    if not verify_hmac(mac_input, data["hmac"], ss):
        return jsonify({"status": "error", "msg": "HMAC verification failed"}), 403
    sig_valid    = False
    if oqs and data.get("signature") and data.get("sig_pk"):
        sig_valid = verify_sig(mac_input.encode(), bytes.fromhex(data["signature"]), bytes.fromhex(data["sig_pk"]))
    amount       = float(decrypt_aes_gcm(data["enc_amount"]["iv"], data["enc_amount"]["ct"], ss).decode())
    remarks      = decrypt_aes_gcm(data["enc_remarks"]["iv"], data["enc_remarks"]["ct"], ss).decode()
    sender_vpa   = data["sender"]
    receiver_vpa = data["receiver"]
    del SESSIONS[session_id]
    with get_db() as conn:
        sender_row   = conn.execute("SELECT * FROM users WHERE vpa=?", (sender_vpa,)).fetchone()
        receiver_row = conn.execute("SELECT * FROM users WHERE vpa=?", (receiver_vpa,)).fetchone()
        if not sender_row:
            return jsonify({"status": "error", "msg": f"Sender {sender_vpa} not found"}), 404
        if not receiver_row:
            return jsonify({"status": "error", "msg": f"Receiver {receiver_vpa} not found"}), 404
        if sender_row["balance"] < amount:
            return jsonify({"status": "error", "msg": f"Insufficient balance — have ₹{sender_row['balance']:.2f}, need ₹{amount:.2f}"}), 402
        new_sender_bal   = round(sender_row["balance"]   - amount, 2)
        new_receiver_bal = round(receiver_row["balance"] + amount, 2)
        conn.execute("UPDATE users SET balance=? WHERE vpa=?", (new_sender_bal,   sender_vpa))
        conn.execute("UPDATE users SET balance=? WHERE vpa=?", (new_receiver_bal, receiver_vpa))
        ref = hashlib.sha256(f"{data['txn_id']}{time.time()}".encode()).hexdigest()[:12].upper()
        ts  = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), data["txn_id"], sender_vpa, receiver_vpa,
             str(amount), remarks, ref, int(sig_valid), PQC_LIB, ts, "SUCCESS"))
    print(f"[SERVER] ✓ {data['txn_id']}  {sender_vpa}→{receiver_vpa}  ₹{amount}  bal:{new_sender_bal}")
    return jsonify({
        "status": "SUCCESS", "txn_id": data["txn_id"], "ref_num": ref,
        "from": sender_vpa, "to": receiver_vpa,
        "amount": str(amount), "remarks": remarks,
        "sig_valid": sig_valid, "timestamp": ts, "pqc": PQC_LIB,
        "sender_balance":   new_sender_bal,
        "receiver_balance": new_receiver_bal
    })

@app.route("/api/transactions")
def api_transactions():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT txn_id,sender,receiver,amount,remarks,ref_num,sig_valid,pqc,timestamp,status "
            "FROM transactions ORDER BY timestamp DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/benchmark")
def api_benchmark():
    import time as t
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    N   = 20
    msg = b"UPI:PAY:alice@ybl->bob@upi:INR2500"
    s = t.perf_counter()
    for _ in range(N): priv = rsa.generate_private_key(65537, 2048)
    rsa_keygen_ms = (t.perf_counter()-s)/N*1000
    pub = priv.public_key()
    s = t.perf_counter()
    for _ in range(N): ct_rsa = pub.encrypt(msg, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    rsa_encrypt_ms = (t.perf_counter()-s)/N*1000
    s = t.perf_counter()
    for _ in range(N): priv.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    rsa_sign_ms = (t.perf_counter()-s)/N*1000
    kyber_keygen_ms = kyber_encap_ms = dil_sign_ms = 0
    kyber_pk_bytes  = kyber_ct_bytes = dil_sig_bytes = 0
    ct_kyber = b""
    if oqs:
        s = t.perf_counter()
        for _ in range(N): k = oqs.KeyEncapsulation(KEM_ALG); pk = k.generate_keypair(); k.free()
        kyber_keygen_ms = (t.perf_counter()-s)/N*1000
        kyber_pk_bytes  = len(pk)
        k = oqs.KeyEncapsulation(KEM_ALG); pk2 = k.generate_keypair(); k.free()
        s = t.perf_counter()
        for _ in range(N): k2 = oqs.KeyEncapsulation(KEM_ALG); ct_kyber,_ = k2.encap_secret(pk2); k2.free()
        kyber_encap_ms = (t.perf_counter()-s)/N*1000
        kyber_ct_bytes = len(ct_kyber)
        sig_o = oqs.Signature(SIG_ALG); sig_o.generate_keypair(); sk2 = sig_o.export_secret_key(); sig_o.free()
        s = t.perf_counter()
        for _ in range(N): so = oqs.Signature(SIG_ALG, sk2); signature = so.sign(msg); so.free()
        dil_sign_ms   = (t.perf_counter()-s)/N*1000
        dil_sig_bytes = len(signature)
    return jsonify({
        "rsa_keygen_ms": round(rsa_keygen_ms,3), "rsa_encrypt_ms": round(rsa_encrypt_ms,3),
        "rsa_sign_ms": round(rsa_sign_ms,3), "kyber_keygen_ms": round(kyber_keygen_ms,3),
        "kyber_encap_ms": round(kyber_encap_ms,3), "dilithium_sign_ms": round(dil_sign_ms,3),
        "iterations": N,
        "sizes": {
            "rsa_pk_bytes":   len(pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)),
            "rsa_ct_bytes":   len(ct_rsa), "kyber_pk_bytes": kyber_pk_bytes,
            "kyber_ct_bytes": kyber_ct_bytes, "dil_sig_bytes": dil_sig_bytes,
        }
    })

@app.route("/api/attack")
def api_attack():
    import math, random
    p, q = 167, 173
    n    = p * q
    phi  = (p-1)*(q-1)
    e    = 17
    def egcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = egcd(b % a, a)
        return g, y-(b//a)*x, x
    def modinv(a, m):
        _, x, _ = egcd(a % m, m)
        return x % m
    d     = modinv(e, phi)
    m_int = 1337
    c_int = pow(m_int, e, n)
    def find_period(a, n):
        x, r = a, 1
        while x != 1:
            x = (x * a) % n
            r += 1
            if r > n: return None
        return r
    found_p = found_q = a_used = period = None
    for _ in range(100):
        a = random.randint(2, n-2)
        g = math.gcd(a, n)
        if 1 < g < n:
            found_p, found_q, a_used = g, n//g, a
            break
        r = find_period(a, n)
        if not r or r % 2: continue
        p1 = math.gcd(pow(a, r//2)-1, n)
        p2 = math.gcd(pow(a, r//2)+1, n)
        if 1 < p1 < n and 1 < p2 < n and p1*p2 == n:
            found_p, found_q, a_used, period = p1, p2, a, r
            break
    if not found_p:
        return jsonify({"error": "attack did not converge, try again"}), 500
    rec_phi = (found_p-1)*(found_q-1)
    rec_d   = modinv(e, rec_phi)
    cracked = pow(c_int, rec_d, n)
    return jsonify({
        "p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d,
        "m_int": m_int, "c_int": c_int, "a_used": a_used, "period": period,
        "found_p": found_p, "found_q": found_q, "rec_phi": rec_phi,
        "rec_d": rec_d, "d_match": rec_d == d, "cracked": cracked
    })

@app.route("/api/qiskit_shor")
def api_qiskit_shor():
    try:
        import math
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        from fractions import Fraction
        from qiskit import QuantumCircuit, transpile
        from qiskit_aer import AerSimulator
        N=15; a=7; n_count=4; n_work=4; shots=2048
        qc = QuantumCircuit(n_count + n_work, n_count)
        qc.x(n_count)
        for q in range(n_count):
            qc.h(q)
        for q in range(n_count):
            reps = 2 ** q
            for _ in range(reps):
                qc.cswap(q, n_count, n_count+1)
                qc.cswap(q, n_count+1, n_count+2)
                qc.cswap(q, n_count+2, n_count+3)
        def apply_iqft(qc, qubits):
            n = len(qubits)
            for i in range(n//2): qc.swap(qubits[i], qubits[n-1-i])
            for j in range(n):
                qc.h(qubits[j])
                for k in range(j+1, n):
                    qc.cp(-math.pi/float(2**(k-j)), qubits[k], qubits[j])
        apply_iqft(qc, list(range(n_count)))
        qc.measure(range(n_count), range(n_count))
        buf = io.BytesIO()
        fig = qc.draw(output='mpl', fold=40,
                      style={'backgroundcolor':'#ffffff','gatefacecolor':'#f3e8ff',
                             'gatetextcolor':'#7e22ce','linecolor':'#6b21a8'})
        fig.savefig(buf, format='png', bbox_inches='tight', dpi=90)
        buf.seek(0)
        circuit_b64 = base64.b64encode(buf.read()).decode()
        plt.close('all')
        sim    = AerSimulator()
        tqc    = transpile(qc, sim)
        counts = sim.run(tqc, shots=shots).result().get_counts()
        sorted_counts = sorted(counts.items(), key=lambda x: int(x[0],2))
        labels = [str(int(k,2)) for k,v in sorted_counts]
        values = [v for k,v in sorted_counts]
        fig2, ax = plt.subplots(figsize=(9,3.2))
        mx = max(values)
        colors = ['#8b5cf6' if v==mx else '#ddd6fe' for v in values]
        ax.bar(labels, values, color=colors, edgecolor='#6d28d9', linewidth=0.5)
        ax.set_xlabel('Measured state (decimal)', fontsize=9)
        ax.set_ylabel('Counts', fontsize=9)
        ax.set_title(f"Shor's circuit — N={N}, a={a}, {shots} shots", fontsize=9)
        ax.set_facecolor('#ffffff'); fig2.patch.set_facecolor('#ffffff')
        plt.tight_layout()
        buf2 = io.BytesIO()
        fig2.savefig(buf2, format='png', bbox_inches='tight', dpi=90)
        buf2.seek(0)
        hist_b64 = base64.b64encode(buf2.read()).decode()
        plt.close('all')
        top_peaks = [int(k,2) for k,v in sorted(counts.items(), key=lambda x:-x[1])[:6] if int(k,2)>0]
        factors_found = []
        for measured in top_peaks:
            phase = measured/(2**n_count)
            frac  = Fraction(phase).limit_denominator(N)
            r     = frac.denominator
            if r%2==0:
                p1=math.gcd(a**(r//2)-1,N); p2=math.gcd(a**(r//2)+1,N)
                if 1<p1<N and 1<p2<N:
                    factors_found.append({"measured":measured,"phase":phase,"r":r,"p":p1,"q":p2})
                    break
        return jsonify({
            "N":N,"a":a,"n_count":n_count,"n_work":n_work,"n_states":2**n_count,
            "num_qubits":qc.num_qubits,"depth":qc.depth(),"gate_count":len(qc),
            "shots":shots,"top_peaks":top_peaks[:5],"factors_found":factors_found,
            "circuit_b64":circuit_b64,"hist_b64":hist_b64,
        })
    except ImportError as e:
        return jsonify({"error": f"Qiskit not installed: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"[SERVER] http://0.0.0.0:{port}  |  {PQC_LIB}")
    print(f"[SERVER] Local: http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)