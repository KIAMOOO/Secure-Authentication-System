# Security Analysis

## Threat Model

### Assets Protected

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

## Threat Actors and Attack Vectors

### 1. External Attackers

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

### 2. Insider Threats

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

### 3. Application-Level Attacks

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
  - CSRF tokens implemented in all forms
  - Token validation on all POST requests
  - Constant-time token comparison to prevent timing attacks
- **Risk Level:** Low (mitigated by CSRF tokens + SameSite cookies)

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

## Security Assumptions

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

## Known Vulnerabilities and Limitations

### High Priority (Production Considerations)

1. **No Rate Limiting**

   - **Vulnerability:** Unlimited login attempts
   - **Impact:** Brute force attacks possible
   - **Mitigation Needed:** Implement rate limiting (e.g., 5 attempts per 15 minutes)
2. **No Account Lockout**

   - **Vulnerability:** Failed login attempts don't lock accounts
   - **Impact:** Persistent brute force attacks
   - **Mitigation Needed:** Lock account after N failed attempts
3. **JSON File Storage**

   - **Vulnerability:** Not suitable for production scale
   - **Impact:** Performance and concurrency issues
   - **Mitigation Needed:** Use proper database (PostgreSQL, MySQL)

### Medium Priority

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

### Low Priority (Educational Context)

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

## Security Mitigations Implemented

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

✅ **CSRF Protection**

- CSRF tokens generated and stored in session
- Tokens included in all forms (register, login, password reset)
- Token validation on all POST requests
- Constant-time comparison (`secrets.compare_digest`) prevents timing attacks
- SameSite cookies provide additional protection

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

