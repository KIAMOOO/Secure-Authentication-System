# System Architecture

## Overview

The Secure Authentication System is designed as a modular, educational demonstration of cryptographic principles and secure authentication practices. The system is organized into clear modules that separate concerns and make the codebase maintainable and understandable.

## System Design

### Architecture Layers

1. **Authentication Layer** (`crypto/auth_system.py`)
   - User registration and management
   - Login with multi-factor authentication
   - JWT token generation and validation
   - Password reset functionality
   - Session management

2. **Cryptographic Layer** (`crypto/`)
   - Symmetric encryption (AES-256)
   - Asymmetric encryption (RSA)
   - Hash functions (SHA-256)
   - Digital signatures (RSA)

3. **Utility Layer** (`utils/`)
   - Secure random number generation
   - Key exchange utilities

4. **Application Layer** (`main.py`)
   - Interactive user interface
   - Menu system
   - User input handling

## Component Details

### Authentication System

The `SecureAuthSystem` class is the core of the application. It manages:
- User storage (in-memory dictionary for demonstration)
- Password hashing using bcrypt
- TOTP secret generation and verification
- JWT token creation and validation
- Session tracking
- Password reset token management

### Encryption Modules

**AESEncryption**: Implements AES-256 symmetric encryption
- Uses PBKDF2 for key derivation
- CBC mode with random IV
- Proper padding for block alignment

**RSAEncryption**: Implements RSA asymmetric encryption
- OAEP padding for security
- Public key encryption, private key decryption
- Suitable for small data or hybrid encryption

### Hash Functions

**SHA256Hash**: SHA-256 hash function implementation
- One-way hash function
- 256-bit output
- Used for data integrity verification

### Digital Signatures

**DigitalSignatures**: RSA-based digital signatures
- PSS padding scheme
- SHA-256 for hashing
- Private key signing, public key verification

## Data Flow

### User Registration Flow

1. User provides username and password
2. Password is hashed with bcrypt
3. TOTP secret is generated
4. User data is stored
5. TOTP secret and QR code URI are returned

### Login Flow

1. User provides username, password, and TOTP code
2. System verifies password hash
3. System verifies TOTP code
4. JWT token is generated
5. Session is created
6. Token and session ID are returned

### Password Reset Flow

1. User requests password reset
2. System generates secure reset token
3. Token is stored with expiration (15 minutes)
4. User receives token (in production, via email)
5. User provides token and new password
6. System validates token and updates password
7. Token is deleted (single-use)

## Security Considerations

### Password Storage
- Passwords are never stored in plain text
- bcrypt with 12 rounds provides good security/speed balance
- Automatic salt generation ensures uniqueness

### Token Security
- JWT tokens use HMAC-SHA256 for signing
- Tokens have expiration times
- Reset tokens are single-use and time-limited

### Encryption
- AES-256 for symmetric encryption
- RSA-2048 for asymmetric encryption
- Proper key derivation using PBKDF2
- Random IVs for each encryption

## Future Improvements

For production use, consider:
- Database integration (PostgreSQL, MySQL)
- Redis for session storage
- Environment variables for secrets
- Rate limiting for API endpoints
- Comprehensive logging and monitoring
- HTTPS enforcement
- Input sanitization and validation
- SQL injection prevention (if using SQL database)
- XSS protection (if web interface)

