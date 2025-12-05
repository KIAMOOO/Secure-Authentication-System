# Architecture

## System Design Overview

The Secure Authentication System follows a **client-server architecture** with a Flask-based web application serving as the backend. The system is designed with security as the primary concern, implementing multiple layers of protection.

## Component Architecture

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

## Data Flow

1. **Registration Flow:**

   - User submits username, email, password → Password validation → Password hashing (bcrypt) → TOTP secret generation → User stored in `users.json`
2. **Authentication Flow:**

   - User submits username + password → Password verification → TOTP code verification → JWT token creation → Session establishment → Redirect to profile
3. **Password Reset Flow:**

   - User requests reset → Token generation → RSA signature → Email/SMS delivery → Token validation → Password update
4. **Profile Access:**

   - Session validation → JWT verification → Cryptographic demos execution → Display results

## Key Design Decisions

- **Stateless JWT tokens** for API-style authentication
- **Stateful Flask sessions** for web UI convenience
- **JSON file storage** for simplicity (educational context)
- **Modular cryptographic functions** for reusability
- **Environment variable configuration** for key management
- **Error handling** at every cryptographic operation

## Code structure

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

