# Secure Authentication Demo (Flask + Python)

## Description

This is a **simple educational web application** that demonstrates a secure
authentication system with modern cryptographic primitives using Python 3
and Flask. The goal is to satisfy university coursework requirements and
to serve as self‑contained example code, **not** to be production ready.

## Features

- **Multi‑factor authentication**: password (hashed with **bcrypt**) + 6‑digit TOTP code (**pyotp**)
- **JWT tokens** for API‑style authentication (**PyJWT**, `HS256` / HMAC‑SHA256)
- **Session management** with signed cookies (Flask session)
- **Password reset** using secure random tokens and RSA‑signed reset links
- **Symmetric encryption** demo using AES‑GCM (`cryptography` library)
- **Asymmetric RSA key pair** for digital signatures (RSA‑PSS + SHA‑256)
- **Toy Diffie–Hellman key exchange** implemented **from scratch in Python**
- All important cryptographic operations are documented with comments and docstrings

## Installation

Requirements: **Python 3.8+** and `pip`.

1. Clone or download this repository.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage Examples

### Start the development server

On Windows PowerShell:

```bash
set FLASK_APP=app.py
set FLASK_ENV=development   # optional, enables debug reload
flask run
```

Open your browser at `http://127.0.0.1:5000/`.

### Register and configure TOTP

1. Go to **Register** and create a new user.
2. After registration, copy the **TOTP secret** into an authenticator app
   (Google Authenticator, Microsoft Authenticator, Authy, etc.).
3. The app will start generating 6‑digit TOTP codes for this account.

### Login with MFA

1. Go to **Login**.
2. Enter your **username** and **password**.
3. Enter the current **6‑digit TOTP code** from the authenticator app.
4. On success you are redirected to the **Profile** page which shows:
   - An AES‑GCM encrypted message and its decrypted form.
   - Result of an RSA signature verification.
   - SHA‑256 hash of a toy Diffie–Hellman shared key.

### Password reset flow

1. Open **Reset Password** and submit your username.
2. A **password‑reset URL** is generated (shown on the page for this demo).
3. Follow the link, set a **new password**, and then log in again
   with the new password + TOTP code.

## Code Documentation

- `app.py` contains detailed comments and docstrings explaining:
  - How each cryptographic primitive is used.
  - Security assumptions and limitations of this demo.
  - How sessions, JWTs, and TOTP verification work together.

## Team Member Contributions

- Aidos — implementation of the Flask application, cryptographic components,
  HTML/CSS styling, and documentation.

If this is a group project, you can expand this section with one bullet
per team member describing their responsibilities.

## License

This project is released under the **MIT License**. See the `LICENSE` file
for full license text.