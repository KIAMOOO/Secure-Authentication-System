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

## Running Tests

The project includes comprehensive unit tests for all cryptographic functions and authentication logic.

**Run all tests:**

```bash
cd C
pytest test_app.py -v
```

**Run specific test class:**

```bash
pytest test_app.py::TestPasswordValidation -v
pytest test_app.py::TestAESEncryption -v
pytest test_app.py::TestRSAEncryption -v
```

The test suite includes **32 tests** covering:

- Password validation and strength requirements
- Password hashing and verification (bcrypt)
- JWT token creation and verification
- AES-GCM symmetric encryption/decryption
- RSA-OAEP asymmetric encryption/decryption
- RSA-PSS digital signatures
- Diffie-Hellman key exchange
- Integration tests for complete workflows

---

## User Guide

### Quick Start

1. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```
2. **Run the application:**

   ```bash
   # Windows PowerShell
   set FLASK_APP=app.py
   flask run

   # Linux/macOS
   export FLASK_APP=app.py
   flask run
   ```
3. **Open your browser:** Navigate to `http://127.0.0.1:5000/`

### Step-by-Step Usage

#### 1. Register a New Account

1. Click **Register** in the navigation menu
2. Fill in the registration form:
   - **Username:** 3-32 characters (letters, numbers, underscores)
   - **Email:** Valid email address (required for password reset)
   - **Password:** Must meet requirements:
     - Minimum 8 characters
     - At least one uppercase letter
     - At least one lowercase letter
     - At least one digit
     - At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
3. Click **Register**
4. **Important:** Save the TOTP secret or scan the QR code with your authenticator app
   - Recommended apps: Google Authenticator, Microsoft Authenticator, Authy
   - The QR code will only be shown once during registration

#### 2. Configure TOTP (Multi-Factor Authentication)

1. After registration, you'll see a **TOTP secret** (base32 string) and **QR code**
2. **Option A - QR Code:**
   - Open your authenticator app
   - Scan the QR code displayed on the page
   - The app will add the account automatically
3. **Option B - Manual Entry:**
   - Copy the TOTP secret
   - Open your authenticator app
   - Add account manually and paste the secret
4. Your authenticator app will now generate **6-digit codes** that change every 30 seconds

#### 3. Login with Multi-Factor Authentication

1. Click **Login** in the navigation menu
2. Enter your **username** and **password**
3. Open your authenticator app and get the current **6-digit TOTP code**
4. Enter the TOTP code in the login form
5. Click **Login**
6. On successful authentication, you'll be redirected to your **Profile** page

**Note:** Both password AND TOTP code must be correct. If either is wrong, login will fail.

#### 4. View Cryptographic Demonstrations

After logging in, visit the **Profile** page to see:

- **AES-GCM Encryption:** Symmetric encryption demonstration

  - Shows encrypted ciphertext
  - Shows decrypted plaintext
  - Demonstrates authenticated encryption
- **RSA-OAEP Encryption:** Asymmetric encryption demonstration

  - Shows RSA-encrypted message
  - Shows decrypted message
  - Demonstrates public-key cryptography
- **RSA Signature Verification:** Digital signature demonstration

  - Shows signature status (valid ✅ or invalid ❌)
  - Demonstrates non-repudiation
- **Diffie-Hellman Key Exchange:** Key exchange demonstration

  - Shows SHA-256 hash of shared secret
  - Demonstrates secure key exchange

#### 5. Reset Your Password

**If you forgot your password:**

1. Click **Reset Password** in the navigation menu
2. Enter your **username**
3. Click **Send reset link**

**If SMTP is configured:**

- Check your email inbox for the password reset link
- Click the link (valid for 15 minutes)
- Enter your new password (must meet strength requirements)
- Login with your new password + TOTP code

**If SMTP is NOT configured:**

- The reset link will be displayed on the page
- Copy the link and open it in your browser
- The link is also printed in the server console
- Enter your new password and login

#### 6. Logout

1. Click **Logout** (available on Profile page)
2. Your session will be cleared
3. You'll be redirected to the home page

### Troubleshooting

**Problem: TOTP code not working**

- Ensure your device's clock is synchronized (TOTP is time-based)
- Check that you're using the correct TOTP secret
- Try waiting for the next code (codes refresh every 30 seconds)

**Problem: Password reset link expired**

- Reset links are valid for 15 minutes only
- Request a new password reset

**Problem: Email not received**

- Check spam/junk folder
- Verify SMTP configuration if email is required
- If SMTP is not configured, check the webpage or server console for the reset link

**Problem: Password doesn't meet requirements**

- Ensure password has:
  - At least 8 characters
  - Uppercase letter
  - Lowercase letter
  - Digit
  - Special character
- Avoid common passwords like "password123!"

### Best Practices

1. **Protect your TOTP secret:** Store it securely or use a backup authenticator app
2. **Use strong passwords:** Follow the complexity requirements
3. **Don't share credentials:** Keep your password and TOTP device private
4. **Logout when done:** Especially on shared computers
5. **Keep authenticator app secure:** Use device lock screen protection

### Email Configuration (SMTP)

The application can send password reset emails using any SMTP server (Mailjet, Gmail, Outlook, etc.). Configure it via environment variables before running the app:

```bash
export SMTP_SERVER="smtp.example.com"
export SMTP_PORT="587"
export SMTP_USERNAME="your-smtp-username-or-api-key"
export SMTP_PASSWORD="your-smtp-password-or-secret"
export FROM_EMAIL="sender@yourdomain.com"
```

**Important notes:**

- `FROM_EMAIL` should be an address **allowed by your SMTP provider** (for example, your Gmail or a verified sender in Mailjet).
- If any of these variables are missing or invalid, **email sending is disabled** and the reset link is displayed on the page and in the console, so the demo remains fully usable.

---

## Architecture

### System Design Overview

The Secure Authentication System follows a **client-server architecture** with a Flask-based web application serving as the backend. The system is designed with security as the primary concern, implementing multiple layers of protection.

### Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Client (Web Browser)                     │
│  - HTML/CSS UI (rendered via Flask templates)               │
│  - TOTP Authenticator App (Google Authenticator, etc.)      │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTPS (in production)
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              Flask Application Server                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Authentication Layer                                 │  │
│  │  - Registration / Login / Logout                      │  │
│  │  - Password Hashing (bcrypt)                         │  │
│  │  - TOTP Verification                                  │  │
│  │  - JWT Token Management                               │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Cryptographic Layer                                  │  │
│  │  - AES-GCM (Symmetric Encryption)                     │  │
│  │  - RSA-OAEP (Asymmetric Encryption)                   │  │
│  │  - RSA-PSS (Digital Signatures)                       │  │
│  │  - Diffie-Hellman (Key Exchange)                     │  │
│  │  - SHA-256 (Hashing)                                  │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Session Management                                   │  │
│  │  - Flask Sessions (signed cookies)                    │  │
│  │  - JWT Tokens (HttpOnly cookies)                     │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Data Persistence Layer                               │  │
│  │  - users.json (user accounts)                        │  │
│  │  - In-memory password reset tokens                    │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Email Service (Optional)                             │  │
│  │  - SMTP Integration                                   │  │
│  │  - Password Reset Emails                              │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Registration Flow:**

   - User submits username, email, password → Password validation → Password hashing (bcrypt) → TOTP secret generation → User stored in `users.json`
2. **Authentication Flow:**

   - User submits username + password → Password verification → TOTP code verification → JWT token creation → Session establishment → Redirect to profile
3. **Password Reset Flow:**

   - User requests reset → Token generation → RSA signature → Email/SMS delivery → Token validation → Password update
4. **Profile Access:**

   - Session validation → JWT verification → Cryptographic demos execution → Display results

### Key Design Decisions

- **Stateless JWT tokens** for API-style authentication
- **Stateful Flask sessions** for web UI convenience
- **JSON file storage** for simplicity (educational context)
- **Modular cryptographic functions** for reusability
- **Environment variable configuration** for key management
- **Error handling** at every cryptographic operation

### Code structure

- **`app.py`** – main Flask application:
  - User **registration**, **login**, **logout**, and **profile**.
  - **TOTP** verification and **JWT** handling.
  - **Password reset** token generation, **RSA signing**, and validation.
  - **SMTP email sending** logic for password‑reset emails.
  - **AES‑GCM** (symmetric), **RSA‑OAEP** (asymmetric encryption), **RSA signatures**, and **Diffie–Hellman** demo code.
  - **Key management** with environment variable support.
  - **Password strength validation** with complexity requirements.
- **`test_app.py`** – unit tests for cryptographic functions and authentication logic (32 tests).
- **`users.json`** – simple JSON "database" used to **persist user accounts** between restarts.

---

## Security Analysis

### Threat Model

#### Assets Protected

1. **User Credentials**

   - Passwords (hashed with bcrypt)
   - TOTP secrets (stored securely)
   - Email addresses
2. **Session Data**

   - JWT tokens
   - Flask session cookies
   - Authentication state
3. **Cryptographic Keys**

   - AES keys (symmetric encryption)
   - RSA key pairs (asymmetric encryption/signatures)
   - JWT signing secrets
4. **User Data**

   - Usernames
   - Email addresses
   - Account information

### Threat Actors and Attack Vectors

#### 1. External Attackers

**Network Eavesdropping:**

- **Threat:** Interception of data in transit
- **Mitigation:** HTTPS requirement in production (not enforced in demo)
- **Risk Level:** High (without HTTPS), Low (with HTTPS)

**Brute Force Attacks:**

- **Threat:** Attempting to guess passwords through repeated trials
- **Mitigation:**
  - Bcrypt hashing (computationally expensive)
  - Strong password requirements
  - TOTP adds second factor
- **Risk Level:** Medium (mitigated by bcrypt + MFA)

**Credential Stuffing:**

- **Threat:** Using leaked credentials from other breaches
- **Mitigation:** Strong password requirements, unique password policy
- **Risk Level:** Medium (mitigated by password complexity)

**Session Hijacking:**

- **Threat:** Stealing session tokens/cookies
- **Mitigation:**
  - HttpOnly cookies (prevents JavaScript access)
  - JWT validation on each request
  - SameSite cookie attribute
- **Risk Level:** Medium (mitigated by HttpOnly + validation)

**Man-in-the-Middle (MITM):**

- **Threat:** Intercepting and modifying communications
- **Mitigation:** HTTPS with certificate validation (production requirement)
- **Risk Level:** High (without HTTPS), Low (with HTTPS)

#### 2. Insider Threats

**Database Access:**

- **Threat:** Unauthorized access to user database
- **Mitigation:**
  - Password hashing (bcrypt) prevents plaintext recovery
  - TOTP secrets stored but require authenticator app
- **Risk Level:** Low (passwords hashed, TOTP requires device)

**Key Compromise:**

- **Threat:** Exposure of cryptographic keys
- **Mitigation:**
  - Environment variable storage
  - Key rotation capability
  - Separate keys for different purposes
- **Risk Level:** Medium (mitigated by key management practices)

#### 3. Application-Level Attacks

**SQL Injection:**

- **Threat:** Injecting malicious SQL queries
- **Mitigation:** Not applicable (using JSON file storage, not SQL database)
- **Risk Level:** None

**Cross-Site Scripting (XSS):**

- **Threat:** Injecting malicious JavaScript
- **Mitigation:**
  - Flask's template escaping
  - HttpOnly cookies prevent token theft
- **Risk Level:** Low (mitigated by Flask escaping)

**Cross-Site Request Forgery (CSRF):**

- **Threat:** Forcing authenticated users to perform actions
- **Mitigation:**
  - SameSite cookies (partial protection)
  - CSRF tokens recommended for production
- **Risk Level:** Medium (partially mitigated, full protection recommended)

**Timing Attacks:**

- **Threat:** Inferring information from response times
- **Mitigation:** Constant-time operations where possible
- **Risk Level:** Low (bcrypt timing is consistent)

**Password Reset Token Attacks:**

- **Threat:** Guessing or intercepting reset tokens
- **Mitigation:**
  - Cryptographically secure random tokens (`secrets.token_urlsafe`)
  - RSA-signed tokens prevent tampering
  - Short expiration (15 minutes)
- **Risk Level:** Low (mitigated by secure tokens + signatures)

### Security Assumptions

1. **HTTPS in Production**

   - All data in transit is encrypted
   - Certificate validation is performed
   - **Note:** Not enforced in demo (development mode)
2. **Secure Server Environment**

   - Keys stored in environment variables are protected by host OS
   - Server has proper access controls
   - No unauthorized physical access
3. **TOTP Secret Protection**

   - Users protect their authenticator apps
   - TOTP secrets are not shared
   - Backup codes are stored securely
4. **Email Delivery Security**

   - SMTP server is trusted and secure
   - Email is delivered to correct recipient
   - Email provider implements proper security
5. **Cryptographic Randomness**

   - `secrets` module and `os.urandom()` provide secure randomness
   - System has sufficient entropy
   - Random number generator is not compromised
6. **Library Security**

   - All cryptographic libraries (`cryptography`, `bcrypt`, `pyotp`, `PyJWT`) are up-to-date
   - No known vulnerabilities in dependencies
   - Libraries are used correctly

### Known Vulnerabilities and Limitations

#### High Priority (Production Considerations)

1. **No Rate Limiting**

   - **Vulnerability:** Unlimited login attempts
   - **Impact:** Brute force attacks possible
   - **Mitigation Needed:** Implement rate limiting (e.g., 5 attempts per 15 minutes)
2. **No Account Lockout**

   - **Vulnerability:** Failed login attempts don't lock accounts
   - **Impact:** Persistent brute force attacks
   - **Mitigation Needed:** Lock account after N failed attempts
3. **Insufficient CSRF Protection**

   - **Vulnerability:** Only SameSite cookies (partial protection)
   - **Impact:** CSRF attacks possible
   - **Mitigation Needed:** Add CSRF tokens to all forms
4. **JSON File Storage**

   - **Vulnerability:** Not suitable for production scale
   - **Impact:** Performance and concurrency issues
   - **Mitigation Needed:** Use proper database (PostgreSQL, MySQL)

#### Medium Priority

5. **Keys Regenerated on Restart**

   - **Vulnerability:** In development mode, keys are not persisted
   - **Impact:** Sessions invalidated on restart
   - **Mitigation:** Already addressed via environment variables
6. **Small Diffie-Hellman Parameters**

   - **Vulnerability:** Educational implementation uses small primes
   - **Impact:** Not cryptographically secure
   - **Mitigation:** Documented as educational only
7. **No Password History**

   - **Vulnerability:** Users can reuse old passwords
   - **Impact:** Security degradation if password was compromised
   - **Mitigation Needed:** Store password hashes history

#### Low Priority (Educational Context)

8. **No HTTPS Enforcement**

   - **Vulnerability:** Demo runs over HTTP
   - **Impact:** Data in transit not encrypted
   - **Mitigation:** Documented as production requirement
9. **No Audit Logging**

   - **Vulnerability:** No record of security events
   - **Impact:** Difficult to detect attacks
   - **Mitigation Needed:** Add logging for failed logins, password resets
10. **No Password Expiration**

    - **Vulnerability:** Passwords never expire
    - **Impact:** Long-term compromise risk
    - **Mitigation Needed:** Implement password age policy

### Security Mitigations Implemented

✅ **Password Security**

- Bcrypt hashing with automatic salt generation
- Strong password requirements (8+ chars, complexity)
- Password reset tokens signed with RSA signatures
- Secure random token generation

✅ **Multi-Factor Authentication**

- Password + TOTP (time-based one-time password)
- TOTP secrets generated securely (`pyotp.random_base32()`)
- Time window validation prevents replay attacks

✅ **Session Security**

- JWT tokens signed with HMAC-SHA256
- HttpOnly cookies prevent JavaScript access
- Session validation on each request
- Token expiration (1 hour)

✅ **Cryptographic Operations**

- AES-GCM for authenticated encryption
- RSA-OAEP for asymmetric encryption
- RSA-PSS for digital signatures
- SHA-256 for hashing
- Secure random number generation (`secrets`, `os.urandom()`)

✅ **Input Validation**

- Username length and format validation
- Email format validation
- Password strength validation
- TOTP code verification with time window

✅ **Error Handling**

- Cryptographic operations wrapped in try-except blocks
- User-friendly error messages without revealing sensitive information
- Secure error handling for JWT verification, password hashing, encryption

✅ **Key Management**

- Environment variable support for all keys
- Secure key generation fallback
- Proper key size validation
- Documentation for key management practices

---

## Team member contributions

This project was developed by a team of three members:

- **Aidos** — Cryptographic components (AES-GCM, RSA-OAEP, RSA-PSS, SHA-256), secure random generation, key management, error handling, password reset with SMTP email.
- **Arsen** — Diffie-Hellman implementation from scratch, bcrypt password hashing, input validation, threat model analysis, architecture documentation, JWT tokens, and session management.
- **Adil** — Flask application, user registration/login, TOTP integration, unit tests, HTML/CSS styling, user guide, and integration tests.

---

## License

This project is released under the **MIT License**.
See the **`LICENSE`** file for the full license text.

