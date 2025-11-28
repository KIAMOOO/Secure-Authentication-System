# Secure Authentication System

## Description

A secure authentication system that implements all required cryptographic components including multi-factor authentication (2FA), JWT tokens, password hashing, and various encryption methods. This project demonstrates practical implementation of cryptographic primitives for educational purposes.

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

1. Install Python 3.8 or higher
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the interactive application:
```bash
python src/main.py
```

Or run from the project root:
```bash
cd src
python main.py
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
