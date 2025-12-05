from __future__ import annotations

import base64
import os
import secrets
import time
from dataclasses import dataclass
import json
from typing import Dict, Optional, Tuple
import urllib.parse
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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


# This is Diffie-Hellman key exchange that we implemented ourselves
# We did it from scratch to show how it works mathematically


@dataclass
class DHParams:
    """This stores the Diffie-Hellman parameters we need.
    
    Warning: The prime number here is small, just for learning!
    In real life you need MUCH bigger primes to be secure.
    We're just showing the math here, not making it unbreakable.
    """

    p: int  # this is the big prime number we use
    g: int  # this is the generator number


def demo_diffie_hellman() -> bytes:
    """This function shows how Diffie-Hellman key exchange works.
    
    We simulate two people (Alice and Bob) exchanging keys.
    Returns the shared secret key as bytes.
    """

    # These are the public numbers everyone can know
    # In real life, people agree on these beforehand
    params = DHParams(
        p=0xFFFFFFFB,  # this is a prime number (but way too small for real use!)
        g=5,  # this is the generator
    )

    # Alice picks a random secret number a, Bob picks secret number b
    # These are private - only each person knows their own number
    a = secrets.randbelow(params.p - 2) + 1
    b = secrets.randbelow(params.p - 2) + 1

    # Now Alice and Bob calculate their public values
    # Everyone can see these, but can't figure out the secret numbers
    A = pow(params.g, a, params.p)  # Alice's public value
    B = pow(params.g, b, params.p)  # Bob's public value

    # Now they exchange public values and calculate the shared secret
    # Both should get the same answer!
    s_alice = pow(B, a, params.p)  # Alice calculates using Bob's public value
    s_bob = pow(A, b, params.p)    # Bob calculates using Alice's public value
    assert s_alice == s_bob  # they should match!

    # Convert the number to bytes and hash it to get a nice key
    shared_bytes = s_alice.to_bytes((s_alice.bit_length() + 7) // 8, "big")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_bytes)
    return digest.finalize()


DEMO_DH_SHARED_KEY = demo_diffie_hellman()


###############################################################################
# Setting up Flask app and all the secret keys we need
###############################################################################

app = Flask(__name__)

# This secret key is used by Flask to sign cookies so people can't fake them
# You can set it yourself with FLASK_SECRET_KEY environment variable if you want
# Otherwise we generate a random one
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

# This is the secret key for signing JWT tokens
# JWT tokens prove that a user is logged in
# You can set it yourself with JWT_SECRET_KEY environment variable
# Otherwise we generate a random one
JWT_SECRET = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
JWT_ALG = "HS256"  # this is the algorithm we use to sign JWTs

# This is the key for AES encryption (symmetric encryption)
# We use 128-bit because it's simpler, but you can use 192 or 256 bits too
# You can set it yourself with AES_KEY_B64 environment variable (base64 encoded)
# Otherwise we generate a new random key
aes_key_env = os.getenv("AES_KEY_B64")
if aes_key_env:
    try:
        AES_KEY = base64.b64decode(aes_key_env.encode("ascii"))
        # AES keys can be 16 bytes (128 bits), 24 bytes (192 bits), or 32 bytes (256 bits)
        if len(AES_KEY) not in [16, 24, 32]:
            raise ValueError("AES key must be 16, 24, or 32 bytes")
    except Exception:
        print("⚠️  Invalid AES_KEY_B64, generating new key")
        AES_KEY = AESGCM.generate_key(bit_length=128)
else:
    AES_KEY = AESGCM.generate_key(bit_length=128)

# These are RSA keys for digital signatures and encryption
# RSA uses two keys: a private key (keep secret!) and a public key (can share)
# You can load your own keys from RSA_PRIVATE_KEY_PEM environment variable
# Otherwise we generate new keys
rsa_private_key_pem = os.getenv("RSA_PRIVATE_KEY_PEM")
if rsa_private_key_pem:
    try:
        # Try to load the key from the environment variable
        RSA_PRIVATE_KEY = serialization.load_pem_private_key(
            rsa_private_key_pem.encode("utf-8"),
            password=None,  # no password on the key
        )
        RSA_PUBLIC_KEY = RSA_PRIVATE_KEY.public_key()  # get public key from private key
    except Exception:
        print("⚠️  Invalid RSA_PRIVATE_KEY_PEM, generating new key pair")
        # If loading failed, just generate new keys
        RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        RSA_PUBLIC_KEY = RSA_PRIVATE_KEY.public_key()
else:
    # No key provided, so generate new ones
    RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    RSA_PUBLIC_KEY = RSA_PRIVATE_KEY.public_key()


###############################################################################
# Our simple "database" - just storing things in memory and a JSON file
###############################################################################


@dataclass
class User:
    """This stores all the info about a user."""
    username: str
    password_hash: bytes  # we store the hashed password, never the real password!
    totp_secret: str  # this is the secret for TOTP codes (base32 format)
    email: str  # user's email address


USERS: Dict[str, User] = {}  # dictionary to store all users in memory

# This stores password reset tokens temporarily
# Format: token -> (username, when it expires)
PASSWORD_RESETS: Dict[str, tuple[str, float]] = {}

# We save users to this JSON file so they don't disappear when we restart the app
USERS_DB_PATH = "users.json"


###############################################################################
# Helper functions - these do useful stuff we need in multiple places
###############################################################################


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Check if a password is strong enough.
    
    Returns:
        (True, "") if password is good, or (False, error_message) if it's weak
    """
    # Check length - at least 8 characters
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password must be no more than 128 characters long."
    
    # Check if it has uppercase letters
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    
    # Check if it has lowercase letters
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    
    # Check if it has numbers
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."
    
    # Check if it has special characters
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character."
    
    # Don't allow super common passwords that everyone uses
    common_passwords = ["password", "12345678", "qwerty", "abc123"]
    if password.lower() in common_passwords:
        return False, "Password is too common. Please choose a stronger password."
    
    # If we got here, password is good!
    return True, ""


def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt so we never store the real password.
    
    Bcrypt automatically adds salt (random data) so the same password
    gets different hashes each time. This makes it much harder to crack.
    """
    # Generate a random salt - bcrypt does this for us automatically
    salt = bcrypt.gensalt()
    # Hash the password with the salt
    return bcrypt.hashpw(password.encode("utf-8"), salt)


def verify_password(password: str, password_hash: bytes) -> bool:
    """Check if a password matches the stored hash.
    
    Returns True if password is correct, False otherwise.
    """

    try:
        # bcrypt.checkpw compares the password to the hash
        return bcrypt.checkpw(password.encode("utf-8"), password_hash)
    except ValueError:
        # If something is wrong with the hash format, just say it's wrong
        return False


def create_jwt(username: str) -> str:
    """Create a JWT token that proves the user is logged in.
    
    JWT = JSON Web Token. It's like a signed note saying "this person is logged in"
    """

    payload = {
        "sub": username,  # subject = who this token is for
        "iat": int(time.time()),  # issued at = when we created it
        "exp": int(time.time()) + 3600,  # expires in 1 hour (3600 seconds)
    }
    # Sign the token with our secret key so nobody can fake it
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    return token


def verify_jwt(token: str) -> Optional[str]:
    """Check if a JWT token is valid and return the username.
    
    Returns the username if token is valid, None if it's fake or expired.
    """

    try:
        # Try to decode and verify the token
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        # Get the username from the token
        return data.get("sub")
    except jwt.PyJWTError:
        # Token is invalid, expired, or fake
        return None


def encrypt_message(plaintext: str) -> str:
    """Encrypt a message using AES-GCM (symmetric encryption).
    
    AES-GCM is good because it encrypts AND checks if someone tampered with it.
    Returns the encrypted message as a base64 string.
    """

    aesgcm = AESGCM(AES_KEY)  # create the encryption object with our key
    nonce = os.urandom(12)  # generate a random nonce (number used once)
    # Encrypt the message - we need the nonce to decrypt it later
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # Combine nonce and ciphertext, then encode as base64 so we can store it
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def decrypt_message(token: str) -> str:
    """Decrypt a message that was encrypted with AES-GCM.
    
    Takes the base64 string and returns the original plaintext.
    """

    # Decode from base64
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    # Split into nonce (first 12 bytes) and ciphertext (the rest)
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(AES_KEY)
    # Decrypt using the same key and nonce
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return plaintext.decode("utf-8")


def sign_data(data: bytes) -> bytes:
    """Create a digital signature using RSA-PSS.
    
    This proves that the data came from us and hasn't been changed.
    Uses our private key to sign, so only we can create valid signatures.
    """

    return RSA_PRIVATE_KEY.sign(
        data,
        padding.PSS(  # PSS is a secure padding scheme for RSA
            mgf=padding.MGF1(hashes.SHA256()),  # mask generation function
            salt_length=padding.PSS.MAX_LENGTH,  # use maximum salt for security
        ),
        hashes.SHA256(),  # hash function to use
    )


def verify_signature(data: bytes, signature: bytes) -> bool:
    """Check if a signature is valid.
    
    Uses the public key to verify - anyone can check signatures,
    but only we can create them (because we have the private key).
    Returns True if signature is valid, False otherwise.
    """

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
        return True  # signature is valid!
    except Exception:
        return False  # signature is invalid or data was tampered with


def encrypt_rsa(plaintext: str) -> str:
    """Encrypt a message using RSA-OAEP (asymmetric encryption).
    
    RSA uses public key to encrypt - anyone can encrypt, but only we can decrypt.
    Warning: RSA can only encrypt small messages (about 190 bytes max for 2048-bit key).
    For bigger messages, you'd use RSA to encrypt an AES key, then AES for the message.
    """
    try:
        # Encrypt using public key with OAEP padding (more secure than old PKCS#1)
        ciphertext = RSA_PUBLIC_KEY.encrypt(
            plaintext.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # mask generation
                algorithm=hashes.SHA256(),  # hash function
                label=None,  # no label needed
            ),
        )
        # Convert to base64 so we can store it as a string
        return base64.urlsafe_b64encode(ciphertext).decode("ascii")
    except Exception as e:
        # If message is too long, RSA can't encrypt it
        return f"ERROR: Message too long for RSA encryption ({str(e)})"


def decrypt_rsa(ciphertext_b64: str) -> str:
    """Decrypt a message that was encrypted with RSA-OAEP.
    
    Only we can decrypt because we have the private key.
    """
    try:
        # Decode from base64
        ciphertext = base64.urlsafe_b64decode(ciphertext_b64.encode("ascii"))
        # Decrypt using private key
        plaintext = RSA_PRIVATE_KEY.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext.decode("utf-8")
    except Exception as e:
        # Something went wrong - maybe wrong key or corrupted data
        return f"ERROR: Decryption failed ({str(e)})"


def load_users_from_disk() -> None:
    """Load all users from the JSON file into memory when app starts.
    
    This way users don't disappear when we restart the server.
    """
    global USERS
    # If file doesn't exist yet, just start with empty dictionary
    if not os.path.exists(USERS_DB_PATH):
        USERS = {}
        return

    try:
        # Read the JSON file
        with open(USERS_DB_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        # If we can't read it, just start fresh
        USERS = {}
        return

    # Convert JSON data back into User objects
    loaded: Dict[str, User] = {}
    for username, record in raw.items():
        try:
            pw_hash_b64 = record["password_hash"]
            totp_secret = record["totp_secret"]
            # Old users might not have email, so use empty string if missing
            email = record.get("email", "")
            loaded[username] = User(
                username=username,
                password_hash=base64.b64decode(pw_hash_b64.encode("ascii")),
                totp_secret=totp_secret,
                email=email,
            )
        except Exception:
            # Skip users with bad data
            continue
    USERS = loaded


def save_users_to_disk() -> None:
    """Save all users to the JSON file so they persist.
    
    We encode password hashes as base64 so they can be stored in JSON.
    """
    data = {}
    for username, user in USERS.items():
        data[username] = {
            "password_hash": base64.b64encode(user.password_hash).decode("ascii"),
            "totp_secret": user.totp_secret,
            "email": user.email,
        }
    try:
        # Write to file
        with open(USERS_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        # If we can't save, just ignore it (not ideal but okay for demo)
        pass


def send_password_reset_email(to_email: str, reset_link: str, username: str) -> Tuple[bool, str]:
    """Send password reset email to the user.
    
    Uses SMTP to send emails. If SMTP isn't configured, we just show the link
    on the webpage instead (for testing).
    
    Returns:
        (True, "") if email sent successfully, or (False, error_message) if failed
    """
    # Get email settings from environment variables
    smtp_server = os.getenv("SMTP_SERVER", "")
    smtp_port_str = os.getenv("SMTP_PORT", "")
    smtp_username = os.getenv("SMTP_USERNAME", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    from_email = os.getenv("FROM_EMAIL", "") or smtp_username
    
    # Check if we have all the settings we need
    if not all([smtp_server, smtp_port_str, smtp_username, smtp_password, from_email]):
        error_msg = (
            "SMTP is not configured. Email will NOT be sent. "
            "The reset link is shown on the page for testing."
        )
        print(f"\n{'='*70}")
        print(f"⚠️  SMTP NOT CONFIGURED - Email sending disabled")
        print(f"{'='*70}")
        print(f"Password Reset Link for {username} ({to_email}):")
        print(f"{reset_link}")
        print(f"{'='*70}")
        print(f"\n📧 To enable email sending, set these environment variables:")
        print(f"  export SMTP_SERVER='smtp.example.com'")
        print(f"  export SMTP_PORT='587'")
        print(f"  export SMTP_USERNAME='your-email@example.com'")
        print(f"  export SMTP_PASSWORD='your-password'")
        print(f"  export FROM_EMAIL='your-email@example.com'")
        print(f"\n💡 Quick setup examples:")
        print(f"  - Mailtrap (for testing): See SIMPLE_SMTP_SETUP.md")
        print(f"  - Outlook: See SIMPLE_SMTP_SETUP.md")
        print(f"{'='*70}\n")
        return False, error_msg
    
    # Convert port string to number
    try:
        smtp_port = int(smtp_port_str)
    except ValueError:
        error_msg = f"Invalid SMTP_PORT value: {smtp_port_str}"
        print(f"❌ Error: {error_msg}")
        return False, error_msg
    
    try:
        # Create the email message
        msg = MIMEMultipart()
        msg["From"] = from_email
        msg["To"] = to_email
        msg["Subject"] = "Password Reset Request - Secure Auth Demo"
        
        # Write the email body text
        body = f"""Hello {username},

You have requested to reset your password for your Secure Auth Demo account.

Please click on the following link to reset your password:

{reset_link}

This link will expire in 15 minutes for security reasons.

If you did not request this password reset, please ignore this email. Your password will remain unchanged.

Best regards,
Secure Auth Demo Team
"""
        
        msg.attach(MIMEText(body, "plain"))
        
        # Actually send the email through SMTP
        print(f"Attempting to send email to {to_email} via {smtp_server}:{smtp_port}...")
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # encrypt the connection
        server.login(smtp_username, smtp_password)  # login to email server
        server.send_message(msg)  # send the email
        server.quit()  # close connection
        
        print(f"✅ Email successfully sent to {to_email}")
        return True, ""
        
    except smtplib.SMTPAuthenticationError as e:
        error_msg = f"Email authentication failed. Please check your SMTP_USERNAME and SMTP_PASSWORD. Error: {str(e)}"
        print(f"\n{'='*70}")
        print(f"❌ EMAIL AUTHENTICATION FAILED")
        print(f"{'='*70}")
        print(f"Error: {error_msg}")
        print(f"Password Reset Link for {username}:")
        print(f"{reset_link}")
        print(f"{'='*70}\n")
        return False, error_msg
        
    except smtplib.SMTPConnectError as e:
        error_msg = f"Cannot connect to SMTP server {smtp_server}:{smtp_port}. Please check your SMTP_SERVER and SMTP_PORT settings. Error: {str(e)}"
        print(f"\n{'='*70}")
        print(f"❌ SMTP CONNECTION FAILED")
        print(f"{'='*70}")
        print(f"Error: {error_msg}")
        print(f"Password Reset Link for {username}:")
        print(f"{reset_link}")
        print(f"{'='*70}\n")
        return False, error_msg
        
    except Exception as e:
        error_msg = f"Failed to send email: {str(e)}"
        print(f"\n{'='*70}")
        print(f"❌ EMAIL SEND FAILED")
        print(f"{'='*70}")
        print(f"Error: {error_msg}")
        print(f"Password Reset Link for {username}:")
        print(f"{reset_link}")
        print(f"{'='*70}\n")
        return False, error_msg


###############################################################################
# HTML templates - we put them here instead of separate files to keep it simple
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
      label { 
        font-size: 0.9rem; 
        color: #374151;
        display: flex;
        flex-direction: column;
        gap: 0.4rem;
      }
      input {
        width: 100%;
        box-sizing: border-box;
        padding: 0.55rem 0.8rem;
        border-radius: 0.55rem;
        border: 1px solid #d1d5db;
        background: #ffffff;
        color: #0f172a;          
        caret-color: #2563eb;    
        font-size: 0.95rem;
        outline: none;
        transition: border-color 0.12s ease, box-shadow 0.12s ease, background 0.12s ease;
      }
      input::placeholder {
        color: #6b7280;          
        opacity: 1;
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
# Flask routes - these handle all the web pages
###############################################################################


@app.route("/health")
def health():
    """Just a simple check to see if the server is running."""
    return "OK", 200


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
    qr_url = None

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        email = (request.form.get("email") or "").strip()

        if not username or not password:
            message = "Username and password are required."
        elif not email:
            message = "Email address is required."
        elif len(username) < 3 or len(username) > 32:
            message = "Username must be between 3 and 32 characters."
        elif username in USERS:
            message = "Username already exists."
        elif "@" not in email or "." not in email.split("@")[1]:
            message = "Please enter a valid email address."
        else:
            # Check if password is strong enough
            is_valid, error_msg = validate_password_strength(password)
            if not is_valid:
                message = error_msg
            else:
                # Hash the password so we don't store it in plain text
                pw_hash = hash_password(password)

                # Generate TOTP secret for 2FA (two-factor authentication)
                # This is what the user will add to their authenticator app
                totp_secret = pyotp.random_base32()
                totp = pyotp.TOTP(totp_secret)
                # Create a URI that authenticator apps can understand
                totp_uri = totp.provisioning_uri(name=username, issuer_name="SecureAuthDemo")
                # Generate QR code URL so user can scan it
                qr_url = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" + urllib.parse.quote(
                    totp_uri
                )

                USERS[username] = User(
                    username=username,
                    password_hash=pw_hash,
                    totp_secret=totp_secret,
                    email=email,
                )
                save_users_to_disk()

                message = "User registered. Configure your TOTP app using the secret below."

    page_content = """
        <form method="post">
          <label>Username
            <input type="text" name="username" required minlength="3" maxlength="32" placeholder="e.g. Kakashi">
          </label>
          
          <label>Email
            <input type="email" name="email" required placeholder="your.email@example.com">
          </label>
          <label>Password
            <input type="password" name="password" required minlength="8" placeholder="Min. 8 chars, uppercase, lowercase, digit, special">
          </label>
          <p style="font-size: 0.85rem; color: #6b7280; margin-top: -0.5rem;">
            Password must be at least 8 characters and include uppercase, lowercase, digit, and special character.
          </p>
          <button type="submit">Register</button>
        </form>
    """
    if totp_secret:
        page_content += f"""
        <h2>Multi-factor setup</h2>
        <p style="color: black;">Add this account to your TOTP app using the following secret:</p>
        <div class="code">{totp_secret}</div>
        <p style="color: black;">Or use this provisioning URI:</p>
        <div class="code">{totp_uri}</div>
        <p style="margin-top: 1rem; color: #b91c1c; font-weight: 500;">
          Scan this QR code with your 2FA authenticator app. If you lose this app and do not have a backup,
          you will lose access to your account.
        </p>
        <div style="margin-top: 0.75rem; display: flex; justify-content: flex-start;">
          <img src="{qr_url}" alt="TOTP QR code"
               style="border-radius: 0.75rem; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.35);" />
        </div>
        """
    return render_template_string(
        BASE_TEMPLATE,
        title="Register",
        message=message,
        totp_uri=totp_uri,
        totp_secret=totp_secret,
        qr_url=qr_url,
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
        # Check if user exists and password is correct
        if not user or not verify_password(password, user.password_hash):
            message = "Invalid username or password."
        else:
            # Check the TOTP code from authenticator app
            totp = pyotp.TOTP(user.totp_secret)
            if not totp.verify(totp_code, valid_window=1):
                message = "Invalid TOTP code."
            else:
                # Both password and TOTP are correct! User is logged in.
                # Create a JWT token to prove they're logged in
                token = create_jwt(username)
                session["username"] = username  # also store in Flask session

                resp = make_response(redirect(url_for("profile")))
                # Set cookie with HttpOnly so JavaScript can't steal the token
                resp.set_cookie(
                    "auth_token",
                    token,
                    httponly=True,  # JavaScript can't read this cookie
                    secure=False,  # set to True when using HTTPS in production
                    samesite="Lax",  # helps prevent CSRF attacks
                )
                return resp

    page_content = """
        <form method="post">
          <label>Username
            <input type="text" name="username" required placeholder="Enter your username">
          </label>
          <label>Password
            <input type="password" name="password" required placeholder="Enter your password">
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
    """Figure out who is logged in right now.
    
    Checks both Flask session and JWT token to make sure user is really logged in.
    Returns the User object if logged in, None otherwise.
    """

    username = session.get("username")
    token = request.cookies.get("auth_token")
    # Need both username and token
    if not username or not token:
        return None

    # Verify the JWT token is valid
    jwt_username = verify_jwt(token)
    # Make sure the username in session matches the token
    if jwt_username != username:
        return None

    # Return the user object
    return USERS.get(username)


@app.route("/profile")
def profile():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    # Show off our encryption - encrypt and decrypt a message
    plaintext = f"Hello {user.username}, this is a confidential message."
    encrypted = encrypt_message(plaintext)  # encrypt with AES
    decrypted = decrypt_message(encrypted)  # decrypt it back

    # Also show RSA encryption (asymmetric)
    rsa_plaintext = f"Secret message for {user.username}"
    rsa_encrypted = encrypt_rsa(rsa_plaintext)
    # Only decrypt if it worked (might fail if message too long)
    rsa_decrypted = decrypt_rsa(rsa_encrypted) if not rsa_encrypted.startswith("ERROR") else rsa_encrypted

    # Create a digital signature to show how signatures work
    data = f"user:{user.username}|ts:{int(time.time())}".encode("utf-8")
    signature = sign_data(data)  # sign it
    sig_ok = verify_signature(data, signature)  # verify the signature

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
                AES‑GCM encrypted message (Symmetric Encryption)
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
                RSA‑OAEP encrypted message (Asymmetric Encryption)
              </div>
              <div class="code">{rsa_encrypted}</div>
            </div>
            <div>
              <div style="font-size:0.85rem; text-transform:uppercase; letter-spacing:0.08em; color:#6b7280; margin-bottom:0.25rem;">
                RSA‑OAEP decrypted plaintext
              </div>
              <div class="code">{rsa_decrypted}</div>
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
    email_sent = False

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        user = USERS.get(username)
        if not user:
            # Don't tell them if user exists or not (security best practice)
            message = "If that account exists, a password reset link has been sent to the registered email address."
        elif not user.email or user.email.strip() == "":
            # User exists but no email on file
            message = "This account does not have an email address registered. Please contact support for assistance."
        else:
            # Generate a random token for password reset
            # Sign it with RSA so nobody can fake it
            raw_token = secrets.token_urlsafe(32)
            expires_at = time.time() + 900  # token expires in 15 minutes
            PASSWORD_RESETS[raw_token] = (username, expires_at)

            # Sign the token and expiration time together
            # This proves the link came from us and hasn't been tampered with
            data = f"{raw_token}|{int(expires_at)}".encode("utf-8")
            signature = base64.urlsafe_b64encode(sign_data(data)).decode("ascii")

            # Create the reset link URL
            reset_link = url_for(
                "reset_password",
                token=raw_token,
                sig=signature,
                _external=True,
            )
            
            # Try to send email with the reset link
            email_sent, error_msg = send_password_reset_email(user.email, reset_link, username)
            
            if email_sent:
                message = "A password reset link has been sent to your registered email address. Please check your inbox."
            else:
                # Email failed, show error (but link will be shown on page for testing)
                message = f"Could not send email. {error_msg}"

    page_content = """
        <form method="post">
          <label>Username
            <input type="text" name="username" required placeholder="Enter your username">
          </label>
          <button type="submit">Send reset link</button>
        </form>
        <p style="margin-top: 1rem; color: #4b5563; font-size: 0.9rem;">
          Enter your username to receive a password reset link via email.
        </p>
    """
    
    # If email didn't work, show the link on the page so we can still test it
    if reset_link and not email_sent:
        page_content += f"""
        <div style="margin-top: 1.5rem; padding: 1rem; background: #fef3c7; border: 1px solid #fcd34d; border-radius: 0.5rem;">
          <h3 style="margin-top: 0; color: #92400e;">Development Mode - Reset Link</h3>
          <p style="color: #78350f; margin-bottom: 0.5rem;">Since email could not be sent, here is your password reset link:</p>
          <div class="code" style="word-break: break-all;">{reset_link}</div>
          <p style="color: #78350f; margin-top: 0.5rem; font-size: 0.85rem;">
            <strong>Note:</strong> Check the server console for email configuration instructions.
          </p>
        </div>
        """
    
    return render_template_string(
        BASE_TEMPLATE,
        title="Request password reset",
        message=message,
        content=page_content,
    )


@app.route("/reset", methods=["GET"])
def reset_password():
    """Check if the reset link is valid, then show password reset form.
    
    Validates the token and RSA signature to make sure link is real.
    """

    # Get the token and signature from the URL
    token = request.args.get("token", "").strip()
    sig_b64 = request.args.get("sig", "").strip()
    message = None
    username = None

    # Check if we got both token and signature
    if not token or not sig_b64:
        print(f"\n⚠️  Reset link validation failed:")
        print(f"   Token present: {bool(token)}")
        print(f"   Signature present: {bool(sig_b64)}")
        print(f"   Full URL: {request.url}")
        message = "Invalid reset link. Please request a new password reset."
    else:
        record = PASSWORD_RESETS.get(token)
        if not record:
            message = "Invalid or expired reset token. Please request a new password reset."
        else:
            username, expires_at = record
            if time.time() > expires_at:
                message = "Reset token has expired. Please request a new password reset."
                username = None
            else:
                # Check the RSA signature to make sure link is real
                data = f"{token}|{int(expires_at)}".encode("utf-8")
                try:
                    # Decode the signature from base64
                    # Sometimes base64 padding gets messed up in URLs, so fix it
                    sig_b64_clean = sig_b64.rstrip("=")  # remove trailing = signs
                    missing_padding = len(sig_b64_clean) % 4
                    if missing_padding:
                        sig_b64_clean += "=" * (4 - missing_padding)  # add padding back
                    
                    # Decode the signature
                    signature = base64.urlsafe_b64decode(sig_b64_clean.encode("ascii"))
                    
                    # Verify the signature matches
                    if not verify_signature(data, signature):
                        print(f"⚠️  Signature verification failed for token: {token[:20]}...")
                        message = "Reset link signature is invalid. Please request a new password reset."
                        username = None
                        
                except Exception as e:
                    # Something went wrong decoding or verifying
                    print(f"❌ Error decoding/verifying signature: {e}")
                    print(f"   Signature length: {len(sig_b64)}")
                    print(f"   Signature preview: {sig_b64[:50]}...")
                    message = "Reset link signature is invalid. Please request a new password reset."
                    username = None

    if username:
        reset_submit_url = url_for("reset_password_submit")
        page_content = f"""
      <p style="color: #4b5563;">Resetting password for <strong>{username}</strong></p>
      <form method="post" action="{reset_submit_url}" style="margin-top: 1rem;">
        <input type="hidden" name="token" value="{token}">
        <label>New password
          <input type="password" name="password" required minlength="8" placeholder="Min. 8 chars, uppercase, lowercase, digit, special">
        </label>
        <p style="font-size: 0.85rem; color: #6b7280; margin-top: -0.5rem;">
          Password must be at least 8 characters and include uppercase, lowercase, digit, and special character.
        </p>
        <button type="submit">Set new password</button>
      </form>
    """



    else:
        request_reset_url = url_for("request_reset")
        page_content = f"""
          <div style="padding: 1rem; background: #fef2f2; border: 1px solid #fecaca; border-radius: 0.5rem; color: #991b1b;">
            <p style="margin: 0;"><strong>Error:</strong> {message}</p>
          </div>
          <p style="margin-top: 1rem;">
            <a href="{request_reset_url}">Request a new password reset</a>
          </p>
        """


    return render_template_string(
        BASE_TEMPLATE,
        title="Reset password",
        message=None,
        username=username,
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
    else:
        username, expires_at = record
        # Check if token expired
        if time.time() > expires_at:
            msg = "Reset token has expired."
        else:
            # Make sure new password is strong enough
            is_valid, error_msg = validate_password_strength(new_password)
            if not is_valid:
                msg = error_msg
            else:
                user = USERS.get(username)
                if not user:
                    msg = "User no longer exists."
                else:
                    # Update the password hash
                    user.password_hash = hash_password(new_password)
                    save_users_to_disk()  # save to file
                    del PASSWORD_RESETS[token]  # delete used token
                    msg = "Password updated. You may now log in."

    login_url = url_for("login")
    page_content = f"""
        <p>{msg}</p>
        <p><a href="{login_url}">Back to login</a></p>
    """

    return render_template_string(
        BASE_TEMPLATE,
        title="Reset password result",
        message=None,
        msg=msg,
        content=page_content,
    )


if __name__ == "__main__":
    # When we start the app, load all users from the file
    load_users_from_disk()
    app.run(debug=True)


