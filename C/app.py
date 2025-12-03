"""
Educational secure authentication demo using Flask.

Security goals / threat model (high level, simplified):
- Protect user passwords at rest by hashing with bcrypt.
- Use multi-factor authentication: something you know (password) +
  something you have (TOTP app like Google Authenticator).
- Use JWT (HMAC-SHA256) as a signed token proving authentication.
- Use HTTPS in real deployments (not shown here) to protect data in transit.

Non-goals / simplifications:
- In-memory "database" (Python dicts) instead of a real DB.
- Keys are generated on each start and not persisted.
- Password reset links are shown in the browser / console instead of email.

This code is intentionally small and heavily commented for learning.
DO NOT copy it directly into production systems.
"""

from __future__ import annotations

import base64
import os
import secrets
import time
from dataclasses import dataclass
import json
from typing import Dict, Optional

import bcrypt
import jwt
import pyotp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import (
    Flask,
    make_response,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)


###############################################################################
# Simple Diffie–Hellman key exchange (implemented "from scratch")
###############################################################################


@dataclass
class DHParams:
    """Small educational Diffie–Hellman parameters.

    NOTE: The prime is intentionally small and not suitable for production.
    The goal is to show the math, not to be unbreakable.
    """

    p: int  # large prime modulus
    g: int  # generator


def demo_diffie_hellman() -> bytes:
    """Perform a tiny DH key exchange between Alice and Bob.

    Returns:
        Shared key bytes derived from the exchange.
    """

    # Public parameters (would normally be agreed beforehand)
    params = DHParams(
        p=0xFFFFFFFB,  # large-ish prime (but still far too small for real use)
        g=5,
    )

    # Alice chooses a random secret a, Bob chooses secret b.
    a = secrets.randbelow(params.p - 2) + 1
    b = secrets.randbelow(params.p - 2) + 1

    # Public values
    A = pow(params.g, a, params.p)
    B = pow(params.g, b, params.p)

    # Shared secrets (should match)
    s_alice = pow(B, a, params.p)
    s_bob = pow(A, b, params.p)
    assert s_alice == s_bob

    # Derive a small key by hashing the integer.
    shared_bytes = s_alice.to_bytes((s_alice.bit_length() + 7) // 8, "big")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_bytes)
    return digest.finalize()


DEMO_DH_SHARED_KEY = demo_diffie_hellman()


###############################################################################
# Application setup, secrets, and RSA keys
###############################################################################

app = Flask(__name__)

# Secret key used by Flask to sign session cookies.
app.secret_key = secrets.token_hex(32)

# Secret key for JWT (HMAC-SHA256).
JWT_SECRET = secrets.token_urlsafe(32)
JWT_ALG = "HS256"

# Symmetric key for AES-GCM. 128-bit here for simplicity.
AES_KEY = AESGCM.generate_key(bit_length=128)

# RSA key pair for digital signatures.
RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PUBLIC_KEY = RSA_PRIVATE_KEY.public_key()


###############################################################################
# In-memory "database"
###############################################################################


@dataclass
class User:
    username: str
    password_hash: bytes
    totp_secret: str  # base32


USERS: Dict[str, User] = {}

# password_reset_token -> (username, expires_at)
PASSWORD_RESETS: Dict[str, tuple[str, float]] = {}

# Simple JSON file used to persist users between restarts so that
# passwords keep working even after you stop and start the app.
USERS_DB_PATH = "users.json"


###############################################################################
# Helper functions
###############################################################################


def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt."""

    # bcrypt automatically handles salt generation when using gensalt().
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt)


def verify_password(password: str, password_hash: bytes) -> bool:
    """Verify a password against a bcrypt hash."""

    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash)
    except ValueError:
        # If password_hash is malformed for some reason.
        return False


def create_jwt(username: str) -> str:
    """Create a signed JWT for a user."""

    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,  # 1 hour validity
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    return token


def verify_jwt(token: str) -> Optional[str]:
    """Verify a JWT and return the username if valid."""

    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return data.get("sub")
    except jwt.PyJWTError:
        return None


def encrypt_message(plaintext: str) -> str:
    """Encrypt a message using AES-GCM."""

    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def decrypt_message(token: str) -> str:
    """Decrypt a message encrypted with AES-GCM."""

    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(AES_KEY)
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return plaintext.decode("utf-8")


def sign_data(data: bytes) -> bytes:
    """Sign data using RSA-PSS and SHA-256."""

    return RSA_PRIVATE_KEY.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(data: bytes, signature: bytes) -> bool:
    """Verify an RSA-PSS signature."""

    try:
        RSA_PUBLIC_KEY.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def load_users_from_disk() -> None:
    """Load users from a small JSON file into the in‑memory USERS dict."""
    global USERS
    if not os.path.exists(USERS_DB_PATH):
        USERS = {}
        return

    try:
        with open(USERS_DB_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        USERS = {}
        return

    loaded: Dict[str, User] = {}
    for username, record in raw.items():
        try:
            pw_hash_b64 = record["password_hash"]
            totp_secret = record["totp_secret"]
            loaded[username] = User(
                username=username,
                password_hash=base64.b64decode(pw_hash_b64.encode("ascii")),
                totp_secret=totp_secret,
            )
        except Exception:
            continue
    USERS = loaded


def save_users_to_disk() -> None:
    """Save USERS dict into a JSON file (password hashes base64‑encoded)."""
    data = {}
    for username, user in USERS.items():
        data[username] = {
            "password_hash": base64.b64encode(user.password_hash).decode("ascii"),
            "totp_secret": user.totp_secret,
        }
    try:
        with open(USERS_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        # For this demo we silently ignore disk errors.
        pass


###############################################################################
# HTML templates (inline for simplicity)
###############################################################################

BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>{{ title }}</title>
    <style>
      :root {
        color-scheme: light dark;
      }
      body {
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        margin: 0;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        background: radial-gradient(circle at top left, #eff6ff, #e0f2fe, #f9fafb);
      }
      .container {
        width: 100%;
        max-width: 720px;
        margin: 2rem;
        background: #ffffff;
        padding: 2.25rem 2.5rem;
        border-radius: 18px;
        box-shadow:
          0 24px 60px rgba(15, 23, 42, 0.18),
          0 0 0 1px rgba(148, 163, 184, 0.18);
      }
      h1 {
        font-size: 1.75rem;
        margin-bottom: 0.75rem;
        color: #0f172a;
        letter-spacing: -0.03em;
      }
      h2 {
        margin-top: 1.5rem;
        margin-bottom: 0.5rem;
        color: #111827;
      }
      a {
        color: #2563eb;
        text-decoration: none;
        font-weight: 500;
      }
      a:hover {
        text-decoration: underline;
      }
      form { display: flex; flex-direction: column; gap: 0.75rem; margin-top: 1rem; }
      label { font-size: 0.9rem; color: #374151; }
      input {
        padding: 0.55rem 0.8rem;
        border-radius: 0.55rem;
        border: 1px solid #d1d5db;
        background: #f9fafb;
        color: #0f172a;          /* ensure text is clearly visible */
        caret-color: #2563eb;    /* blue text cursor for visibility */
        font-size: 0.95rem;
        outline: none;
        transition: border-color 0.12s ease, box-shadow 0.12s ease, background 0.12s ease;
      }
      input:focus {
        border-color: #2563eb;
        background: #ffffff;
        box-shadow: 0 0 0 1px rgba(37, 99, 235, 0.4);
      }
      button {
        margin-top: 0.5rem;
        padding: 0.7rem 1.4rem;
        border-radius: 999px;
        border: none;
        background: linear-gradient(135deg, #1d4ed8, #2563eb, #4f46e5);
        color: white;
        cursor: pointer;
        font-weight: 600;
        letter-spacing: 0.02em;
        box-shadow: 0 12px 30px rgba(37, 99, 235, 0.35);
        transition: transform 0.12s ease, box-shadow 0.12s ease, filter 0.12s ease;
      }
      button:hover {
        transform: translateY(-1px);
        box-shadow: 0 18px 40px rgba(37, 99, 235, 0.45);
        filter: brightness(1.03);
      }
      button:active {
        transform: translateY(0);
        box-shadow: 0 10px 20px rgba(37, 99, 235, 0.4);
      }
      .nav {
        margin-bottom: 1.25rem;
        display: flex;
        flex-wrap: wrap;
        gap: 0.75rem;
        font-size: 0.9rem;
        color: #64748b;
      }
      .nav a {
        padding: 0.3rem 0.75rem;
        border-radius: 999px;
        background: #eff6ff;
        border: 1px solid transparent;
      }
      .nav a:hover {
        background: #dbeafe;
        border-color: #bfdbfe;
      }
      .flash {
        margin-top: 1rem;
        padding: 0.8rem 1rem;
        border-radius: 0.75rem;
        background: #eff6ff;
        color: #1d4ed8;
        border: 1px solid #bfdbfe;
      }
      .code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
              background: #020617; color: #e5e7eb; padding: 0.75rem 0.9rem; border-radius: 0.6rem; font-size: 0.8rem; white-space: pre-wrap; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="nav">
        <a href="{{ url_for('index') }}">Home</a>
        <a href="{{ url_for('register') }}">Register</a>
        <a href="{{ url_for('login') }}">Login</a>
        <a href="{{ url_for('profile') }}">Profile</a>
        <a href="{{ url_for('request_reset') }}">Reset Password</a>
      </div>
      <h1>{{ title }}</h1>
      {% if message %}
        <div class="flash">{{ message }}</div>
      {% endif %}
      {{ content|safe }}
    </div>
  </body>
</html>
"""


###############################################################################
# Routes
###############################################################################


@app.route("/")
def index():
    page_content = """
        <p style="max-width: 40rem; color:#4b5563; line-height:1.6;">
          This mini web app demonstrates a modern secure authentication system built with Python and Flask.
          It is intentionally small and easy to read so you can study each cryptographic building block.
        </p>

        <div style="display:flex; flex-wrap:wrap; gap:1rem; margin-top:1.25rem;">
          <div style="flex:1 1 180px; padding:0.9rem 1rem; border-radius:0.9rem; background:#f1f5f9;">
            <h2 style="margin-top:0; font-size:1rem;">Authentication</h2>
            <ul style="margin:0; padding-left:1.1rem; color:#4b5563; font-size:0.9rem;">
              <li>Password hashing with bcrypt</li>
              <li>Password + TOTP (multi‑factor)</li>
              <li>JWT tokens & secure sessions</li>
            </ul>
          </div>
          <div style="flex:1 1 180px; padding:0.9rem 1rem; border-radius:0.9rem; background:#f1f5f9;">
            <h2 style="margin-top:0; font-size:1rem;">Cryptography</h2>
            <ul style="margin:0; padding-left:1.1rem; color:#4b5563; font-size:0.9rem;">
              <li>AES‑GCM symmetric encryption</li>
              <li>RSA digital signatures</li>
              <li>Toy Diffie–Hellman key exchange</li>
            </ul>
          </div>
        </div>

        <p style="margin-top:1.25rem; color:#4b5563;">
          To explore, first <strong>Register</strong> a user, set up TOTP in an authenticator app,
          then <strong>Login</strong> and open your <strong>Profile</strong> to see the crypto demos.
        </p>
    """
    return render_template_string(
        BASE_TEMPLATE,
        title="Secure Auth Demo",
        message=None,
        content=page_content,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    message = None
    totp_uri = None
    totp_secret = None

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            message = "Username and password are required."
        elif len(username) < 3 or len(username) > 32:
            message = "Username must be between 3 and 32 characters."
        elif username in USERS:
            message = "Username already exists."
        else:
            pw_hash = hash_password(password)

            # Generate TOTP secret and provisioning URI for authenticator apps.
            totp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(totp_secret)
            totp_uri = totp.provisioning_uri(name=username, issuer_name="SecureAuthDemo")

            USERS[username] = User(
                username=username,
                password_hash=pw_hash,
                totp_secret=totp_secret,
            )
            save_users_to_disk()

            message = "User registered. Configure your TOTP app using the secret below."

    page_content = """
        <form method="post">
          <label>Username
            <input type="text" name="username" required minlength="3" maxlength="32">
          </label>
          <label>Password
            <input type="password" name="password" required minlength="6">
          </label>
          <button type="submit">Register</button>
        </form>
    """
    if totp_secret:
        page_content += f"""
        <h2>Multi-factor setup</h2>
        <p>Add this account to your TOTP app using the following secret:</p>
        <div class="code">{totp_secret}</div>
        <p style="color: black;">Or use this provisioning URI:</p>
        <div class="code">{totp_uri}</div>
        """
    return render_template_string(
        BASE_TEMPLATE,
        title="Register",
        message=message,
        totp_uri=totp_uri,
        totp_secret=totp_secret,
        content=page_content,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    message = None

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        totp_code = (request.form.get("totp") or "").strip()

        user = USERS.get(username)
        if not user or not verify_password(password, user.password_hash):
            message = "Invalid username or password."
        else:
            # Verify TOTP code
            totp = pyotp.TOTP(user.totp_secret)
            if not totp.verify(totp_code, valid_window=1):
                message = "Invalid TOTP code."
            else:
                # Both password and TOTP are correct. Create JWT and session.
                token = create_jwt(username)
                session["username"] = username

                resp = make_response(redirect(url_for("profile")))
                # HttpOnly helps prevent JavaScript from reading the token.
                resp.set_cookie(
                    "auth_token",
                    token,
                    httponly=True,
                    secure=False,  # set True when using HTTPS
                    samesite="Lax",
                )
                return resp

    page_content = """
        <form method="post">
          <label>Username
            <input type="text" name="username" required>
          </label>
          <label>Password
            <input type="password" name="password" required>
          </label>
          <label>TOTP Code
            <input type="text" name="totp" required placeholder="123456">
          </label>
          <button type="submit">Login</button>
        </form>
    """
    return render_template_string(
        BASE_TEMPLATE,
        title="Login",
        message=message,
        content=page_content,
    )


def get_current_user() -> Optional[User]:
    """Return the currently logged-in user based on session and JWT."""

    username = session.get("username")
    token = request.cookies.get("auth_token")
    if not username or not token:
        return None

    jwt_username = verify_jwt(token)
    if jwt_username != username:
        return None

    return USERS.get(username)


@app.route("/profile")
def profile():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    # Demonstrate encryption and signatures on a small message.
    plaintext = f"Hello {user.username}, this is a confidential message."
    encrypted = encrypt_message(plaintext)
    decrypted = decrypt_message(encrypted)

    data = f"user:{user.username}|ts:{int(time.time())}".encode("utf-8")
    signature = sign_data(data)
    sig_ok = verify_signature(data, signature)

    logout_url = url_for("logout")

    page_content = f"""
        <p style="color:#4b5563; max-width:38rem;">
          Welcome, <strong>{user.username}</strong>! You are logged in using password + TOTP (multi‑factor authentication).
          Below you can see a few cryptographic operations performed just for your session.
        </p>

        <section style="margin-top:1.75rem;">
          <h2 style="margin-bottom:0.5rem;">Crypto demos</h2>
          <div style="display:flex; flex-direction:column; gap:0.75rem;">
            <div>
              <div style="font-size:0.85rem; text-transform:uppercase; letter-spacing:0.08em; color:#6b7280; margin-bottom:0.25rem;">
                AES‑GCM encrypted message
              </div>
              <div class="code">{encrypted}</div>
            </div>
            <div>
              <div style="font-size:0.85rem; text-transform:uppercase; letter-spacing:0.08em; color:#6b7280; margin-bottom:0.25rem;">
                Decrypted plaintext
              </div>
              <div class="code">{decrypted}</div>
            </div>
            <div>
              <div style="font-size:0.85rem; text-transform:uppercase; letter-spacing:0.08em; color:#6b7280; margin-bottom:0.25rem;">
                RSA signature check
              </div>
              <div class="code">Signature status: {"valid ✅" if sig_ok else "INVALID ❌"}</div>
            </div>
          </div>
        </section>

        <section style="margin-top:1.75rem;">
          <h2 style="margin-bottom:0.5rem;">Diffie–Hellman shared key (demo)</h2>
          <p style="color:#4b5563; max-width:36rem; margin-top:0;">
            This is the SHA‑256 hash (hex encoded) of a toy Diffie–Hellman shared secret
            computed between an \"Alice\" and \"Bob\" inside the server.
          </p>
          <div class="code">{DEMO_DH_SHARED_KEY.hex()}</div>
        </section>

        <p style="margin-top:1.75rem;">
          <a href="{logout_url}">Logout</a>
        </p>
    """
    return render_template_string(
        BASE_TEMPLATE,
        title="Profile",
        message=None,
        user=user,
        encrypted=encrypted,
        decrypted=decrypted,
        sig_ok=sig_ok,
        dh_key_hex=DEMO_DH_SHARED_KEY.hex(),
        content=page_content,
    )


@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("auth_token")
    return resp


@app.route("/request-reset", methods=["GET", "POST"])
def request_reset():
    message = None
    reset_link = None

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        user = USERS.get(username)
        if not user:
            message = "If that account exists, a reset link has been generated."
        else:
            # Generate a random reset token and sign it with RSA.
            raw_token = secrets.token_urlsafe(32)
            expires_at = time.time() + 900  # 15 minutes
            PASSWORD_RESETS[raw_token] = (username, expires_at)

            # For demonstration, we sign the token+expiry and include it in the URL as well.
            data = f"{raw_token}|{int(expires_at)}".encode("utf-8")
            signature = base64.urlsafe_b64encode(sign_data(data)).decode("ascii")

            reset_link = url_for(
                "reset_password",
                token=raw_token,
                sig=signature,
                _external=True,
            )
            message = "Password reset link (for demo) is shown below. In a real app it would be emailed."

    page_content = """
        <form method="post">
          <label>Username
            <input type="text" name="username" required>
          </label>
          <button type="submit">Send reset link</button>
        </form>
    """
    if reset_link:
        page_content += f"""
        <h2>Reset link</h2>
        <div class="code">{reset_link}</div>
        """
    return render_template_string(
        BASE_TEMPLATE,
        title="Request password reset",
        message=message,
        reset_link=reset_link,
        content=page_content,
    )


@app.route("/reset")
def reset_password():
    """Validate reset token and signature, then show password reset form."""

    token = request.args.get("token") or ""
    sig_b64 = request.args.get("sig") or ""
    message = None

    record = PASSWORD_RESETS.get(token)
    if not record:
        message = "Invalid or expired reset token."
        username = None
    else:
        username, expires_at = record
        if time.time() > expires_at:
            message = "Reset token has expired."
            username = None
        else:
            # Verify RSA signature on token|expiry
            data = f"{token}|{int(expires_at)}".encode("utf-8")
            try:
                signature = base64.urlsafe_b64decode(sig_b64.encode("ascii"))
            except Exception:
                signature = b""

            if not verify_signature(data, signature):
                message = "Reset link signature is invalid."
                username = None

    if locals().get("username"):
        page_content = f"""
          <p>Resetting password for <strong>{username}</strong></p>
          <form method="post" action="{{ url_for('reset_password_submit') }}">
            <input type="hidden" name="token" value="{token}">
            <label>New password
              <input type="password" name="password" required minlength="6">
            </label>
            <button type="submit">Set new password</button>
          </form>
        """
    else:
        page_content = f"""
          <p>Cannot reset password: {message}</p>
        """
    return render_template_string(
        BASE_TEMPLATE,
        title="Reset password",
        message=None if not message or "token" in message.lower() else message,
        username=locals().get("username"),
        token=token,
        content=page_content,
    )


@app.route("/reset-submit", methods=["POST"])
def reset_password_submit():
    token = request.form.get("token") or ""
    new_password = request.form.get("password") or ""

    record = PASSWORD_RESETS.get(token)
    if not record:
        msg = "Invalid or expired reset token."
    elif len(new_password) < 6:
        msg = "Password is too short."
    else:
        username, expires_at = record
        if time.time() > expires_at:
            msg = "Reset token has expired."
        else:
            user = USERS.get(username)
            if not user:
                msg = "User no longer exists."
            else:
                user.password_hash = hash_password(new_password)
                save_users_to_disk()
                del PASSWORD_RESETS[token]
                msg = "Password updated. You may now log in."

    page_content = f"""
        <p>{msg}</p>
        <p><a href="{{ url_for('login') }}">Back to login</a></p>
    """
    return render_template_string(
        BASE_TEMPLATE,
        title="Reset password result",
        message=None,
        msg=msg,
        content=page_content,
    )


if __name__ == "__main__":
    # Load users from disk once on startup so credentials survive restarts.
    load_users_from_disk()
    # Running via `python app.py` for convenience.
    app.run(debug=True)


