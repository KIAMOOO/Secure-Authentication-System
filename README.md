# Secure Authentication System

## Description

Secure Authentication System is an educational-grade platform that showcases a full authentication flow built on modern cryptographic primitives. The goal is to walk students and reviewers through how multi-factor authentication, JWT-based sessions, password hashing, and encryption/signature pipelines work together in a cohesive security architecture.

## Features

- **Multi-factor Authentication (2FA)**: TOTP-based two-factor authentication
- **JWT Token Management**: Secure token generation and validation using HMAC-SHA256
- **Password Security**: bcrypt password hashing with automatic salting
- **Symmetric Encryption**: AES-256 encryption for data protection
- **Asymmetric Encryption**: RSA encryption for secure communication
- **Hash Functions**: SHA-256 for data integrity verification
- **Digital Signatures**: RSA-based digital signatures for authentication
- **Key Exchange**: Public key sharing for secure key exchange
- **Password Reset**: Secure token-based password reset mechanism
- **Session Management**: Secure session tracking with expiration

## Installation

1. Install Python 3.8 or higher.
2. (Optional) Create and activate a virtual environment.
3. Install dependencies from the project root:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the health check to verify dependencies:
   ```bash
   python -c "import pyotp, jwt, bcrypt, cryptography"
   ```

## Usage

Run the interactive console demo from the project root:
```bash
python src/main.py
```

Or enter the `src` directory first:
```bash
cd src
python main.py
```

### Usage Examples

#### 1. Register a user with enforced 2FA
```
Select option 1 → provide username/password → store the displayed TOTP secret or scan the QR URI in an authenticator app.
```

#### 2. Perform a full MFA login
```
Select option 2 → enter the registered username/password → open your authenticator app to read the 6-digit TOTP code → paste the code to receive a signed JWT token.
```

#### 3. Verify and inspect a JWT session
```
Copy the token from the login step → select option 4 → paste the token to see the decoded payload, signature validation result, and expiration timestamp.
```

#### 4. Run the scripted end‑to‑end demo
```
Select option 11 to automatically register a demo account, log in with generated TOTP, and exercise every cryptographic component (AES, RSA, SHA-256, signatures, key exchange, secure randomness).
```

## Project Structure

```
project-name/
├── README.md              # Project overview
├── LICENSE                # License file
├── requirements.txt       # Python dependencies
├── .gitignore            # Git ignore file
├── src/                  # Source code
│   ├── main.py           # Entry point
│   ├── crypto/           # Cryptographic modules
│   │   ├── __init__.py
│   │   ├── auth_system.py
│   │   ├── encryption.py
│   │   ├── hashing.py
│   │   └── signatures.py
│   ├── utils/            # Utility functions
│   │   ├── __init__.py
│   │   ├── random_generator.py
│   │   └── key_exchange.py
│   └── tests/            # Unit tests
│       └── __init__.py
└── docs/                 # Documentation
    ├── architecture.md   # System design
    └── security.md       # Security analysis
```

## Cryptographic Components

This project implements all mandatory cryptographic components:

1. **Symmetric Encryption (AES-256)**: Fast and efficient encryption for large data
2. **Asymmetric Encryption (RSA)**: Public/private key encryption for secure communication
3. **Hash Functions (SHA-256)**: One-way hashing for data integrity
4. **Digital Signatures (RSA)**: Cryptographic signatures for authentication
5. **Key Exchange**: Secure public key sharing mechanism
6. **Password Hashing (bcrypt)**: Secure password storage with automatic salting
7. **Secure Random Generation**: Cryptographically secure random number generation

## Security Features

- Passwords are never stored in plain text
- TOTP-based 2FA for additional security layer
- JWT tokens with HMAC-SHA256 signatures
- Secure password reset tokens with expiration
- Session management with automatic expiration
- Input validation and error handling

## Documentation

- [Architecture Documentation](docs/architecture.md) - System design and architecture
- [Security Analysis](docs/security.md) - Security assumptions and threat model

## Team & Contributions

- **Aidos Arsen Adil** — project lead, cryptographic implementation, interactive runner, and documentation.

## Requirements

- Python 3.8+
- bcrypt >= 4.0.0
- pyotp >= 2.9.0
- PyJWT >= 2.8.0
- cryptography >= 41.0.0

## Learning Resources

This project is designed for educational purposes. All code includes detailed comments explaining:
- What each function does
- Why we do things a certain way
- How cryptographic operations work
- Security best practices

## Important Notes

- This is a **demonstration/learning project**
- In production, you would:
  - Use a real database (PostgreSQL, MySQL, etc.)
  - Store secrets in environment variables
  - Use HTTPS for all communications
  - Implement rate limiting
  - Add logging and monitoring
  - Use proper session storage (Redis, etc.)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
