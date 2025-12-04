# Secure Authentication Demo (Flask + Python)

## Description

This is a **simple educational web application** that demonstrates a **secure authentication system** with modern cryptographic primitives using **Python 3** and **Flask**. It is designed for **university coursework and learning**, not for production deployment.

## Features

- **Multi‑factor authentication (MFA)**: password (hashed with **bcrypt**) + 6‑digit TOTP code (**pyotp**).
- **JWT tokens** for API‑style authentication (**PyJWT**, `HS256` / HMAC‑SHA256).
- **Session management** with signed cookies (Flask session).
- **Password reset** using secure random tokens and **RSA‑signed reset links**.
- **Password‑reset emails via SMTP** (Mailjet, Gmail, Outlook, etc.).
- **Symmetric encryption demo** using **AES‑GCM** (`cryptography` library).
- **Asymmetric RSA key pair** for **digital signatures** (RSA‑PSS + SHA‑256).
- **Toy Diffie–Hellman key exchange** implemented from scratch in Python.
- Clear, heavily commented code aimed at understanding each building block.

---

## Installation

Requirements: **Python 3.8+** and **`pip`**.

1. Clone or download this repository.
2. Install dependencies:

```
pip install -r requirements.txt
```



---

## Running the app

**On Windows PowerShell:**

```
set FLASK_APP=app.py
set FLASK_ENV=development # optional, enables debug reload
flask run
```


**On Linux/macOS:**

```
export FLASK_APP=app.py
export FLASK_ENV=development # optional
flask run
```


Open your browser at [**http://127.0.0.1:5000/**](http://127.0.0.1:5000/).

---

## Usage

### Register and configure TOTP

1. Go to **Register** and create a new user (**username, email, password**).
2. After registration, add the shown **TOTP secret or QR code** to an authenticator app  
   (Google Authenticator, Microsoft Authenticator, Authy, etc.).
3. The app will start generating **6‑digit TOTP codes** for this account.

### Login with MFA

1. Go to **Login**.
2. Enter your **username** and **password**.
3. Enter the current **6‑digit TOTP code** from the authenticator app.
4. On success you are redirected to the **Profile** page, which shows:
   - An **AES‑GCM encrypted message** and its **decrypted** form.
   - Result of an **RSA signature verification**.
   - **SHA‑256 hash** of a toy **Diffie–Hellman shared key**.

### Password reset flow

1. Open **Reset Password** and submit your **username**.
2. If **SMTP is configured**, a **password‑reset link** is sent to the registered email address.
3. Click the reset link (**valid for 15 minutes**).
4. Choose a **new password**, then log in again with the new password + TOTP code.

> 💡 If SMTP is **not** configured, the reset link is shown directly on the page  
> and printed in the server console so the flow can still be tested.

---

## Email configuration (SMTP)

The application can send real **password‑reset emails** using any SMTP server (Mailjet, Gmail, Outlook, etc.).  
Configure it via **environment variables** before running the app:

```
export SMTP_SERVER="smtp.example.com"
export SMTP_PORT="587"
export SMTP_USERNAME="your-smtp-username-or-api-key"
export SMTP_PASSWORD="your-smtp-password-or-secret"
export FROM_EMAIL="sender@yourdomain.com"
 ```


**Important notes:**

- `FROM_EMAIL` should be an address **allowed by your SMTP provider**  
  (for example, your Gmail or a **verified sender in Mailjet**).
- If any of these variables are missing or invalid, **email sending is disabled** and the reset link is
  displayed on the **page** and in the **console**, so the demo remains fully usable.


## Code structure

- **`app.py`** – main Flask application:
  - User **registration**, **login**, **logout**, and **profile**.
  - **TOTP** verification and **JWT** handling.
  - **Password reset** token generation, **RSA signing**, and validation.
  - **SMTP email sending** logic for password‑reset emails.
  - **AES‑GCM**, **RSA signatures**, and **Diffie–Hellman** demo code.
- **`users.json`** – simple JSON “database” used to **persist user accounts** between restarts.

---

## Team member contributions

- **Adil** — backend logic, JWT/session handling, and password reset flow.
- **Arsen** — cryptographic components (AES‑GCM, RSA signatures, Diffie–Hellman demo) and security comments/docstrings.
- **Aidos** — Flask application implementation, cryptographic components, password‑reset and email flow,
  HTML/CSS styling, and project documentation (README and setup guides).

---

## License

This project is released under the **MIT License**.  
See the **`LICENSE`** file for the full license text.


