"""
Main authentication system class.
Handles user registration, login, JWT tokens, TOTP, and password reset.
"""

import bcrypt
import pyotp
import jwt
import secrets
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class SecureAuthSystem:
    """
    This class handles user authentication with multiple security features.
    Think of it like a secure door system that checks multiple things before letting you in.
    """
    
    def __init__(self):
        # This is like a simple database to store users
        # In a real system, we'd use a proper database like PostgreSQL
        self.users = {}
        
        # Store active sessions (like keeping track of who's logged in)
        self.sessions = {}
        
        # Store password reset tokens (temporary codes to reset passwords)
        self.reset_tokens = {}
        
        # Generate RSA keys for digital signatures and encryption
        # RSA is used for asymmetric encryption (public/private key pair)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard value for RSA
            key_size=2048,  # 2048 bits is secure
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Secret key for JWT signing (in production, this should be in environment variables)
        self.jwt_secret = secrets.token_bytes(32)  # 32 bytes = 256 bits
        
        print("[OK] Authentication system initialized")
        print("[OK] RSA keys generated for encryption and signatures")
    
    # ==================== PASSWORD HASHING ====================
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt.
        
        Why hash passwords?
        - If someone steals our database, they can't see actual passwords
        - bcrypt automatically adds salt (random data) to make each hash unique
        - It's slow by design to prevent brute force attacks
        """
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=12)  # 12 rounds = good balance of security and speed
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Check if a password matches the stored hash."""
        password_bytes = password.encode('utf-8')
        hashed_bytes = hashed.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    
    # ==================== USER REGISTRATION ====================
    
    def register_user(self, username: str, password: str) -> dict:
        """
        Register a new user in the system.
        
        Steps:
        1. Hash the password (never store plain text!)
        2. Generate a TOTP secret (for 2FA)
        3. Store user info securely
        """
        if username in self.users:
            return {"error": "Username already exists"}
        
        password_hash = self.hash_password(password)
        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)
        
        self.users[username] = {
            "password_hash": password_hash,
            "totp_secret": totp_secret,
            "created_at": datetime.now().isoformat()
        }
        
        qr_uri = totp.provisioning_uri(
            name=username,
            issuer_name="SecureAuthSystem"
        )
        
        print(f"[OK] User '{username}' registered successfully")
        
        return {
            "success": True,
            "username": username,
            "totp_secret": totp_secret,
            "qr_uri": qr_uri,
            "message": "Please save your TOTP secret and set up 2FA"
        }
    
    # ==================== LOGIN WITH 2FA ====================
    
    def login(self, username: str, password: str, totp_code: str) -> dict:
        """
        Login a user with password and TOTP code.
        
        Multi-factor authentication (2FA) means we need:
        1. Something you know (password)
        2. Something you have (TOTP code from your phone)
        """
        if username not in self.users:
            return {"error": "Invalid username or password"}
        
        user = self.users[username]
        
        # Step 1: Verify password
        if not self.verify_password(password, user["password_hash"]):
            return {"error": "Invalid username or password"}
        
        # Step 2: Verify TOTP code
        totp = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(totp_code, valid_window=1):
            return {"error": "Invalid TOTP code"}
        
        # Both checks passed! Now generate JWT token
        jwt_token = self.generate_jwt_token(username)
        
        # Create session
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            "username": username,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=24)).isoformat()
        }
        
        print(f"[OK] User '{username}' logged in successfully")
        
        return {
            "success": True,
            "token": jwt_token,
            "session_id": session_id,
            "expires_in": 3600
        }
    
    # ==================== JWT TOKEN GENERATION ====================
    
    def generate_jwt_token(self, username: str) -> str:
        """
        Generate a JWT token for authenticated users.
        
        JWT tokens contain:
        - Header: algorithm info (HMAC-SHA256)
        - Payload: user data (username, expiration time)
        - Signature: cryptographic signature to prevent tampering
        """
        expiration = datetime.now(timezone.utc) + timedelta(hours=1)
        
        payload = {
            "username": username,
            "exp": expiration.timestamp(),
            "iat": datetime.now(timezone.utc).timestamp(),
            "iss": "SecureAuthSystem"
        }
        
        token = jwt.encode(
            payload,
            self.jwt_secret,
            algorithm="HS256"  # HMAC-SHA256
        )
        
        return token
    
    def verify_jwt_token(self, token: str) -> dict:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"]
            )
            return {"valid": True, "payload": payload}
        except jwt.ExpiredSignatureError:
            return {"valid": False, "error": "Token has expired"}
        except jwt.InvalidTokenError:
            return {"valid": False, "error": "Invalid token"}
    
    # ==================== PASSWORD RESET ====================
    
    def request_password_reset(self, username: str) -> dict:
        """Request a password reset. Generates a secure token."""
        if username not in self.users:
            return {"success": True, "message": "If user exists, reset link sent"}
        
        reset_token = secrets.token_urlsafe(32)
        
        self.reset_tokens[reset_token] = {
            "username": username,
            "expires_at": (datetime.now() + timedelta(minutes=15)).isoformat()
        }
        
        print(f"[OK] Password reset token generated for '{username}'")
        
        return {
            "success": True,
            "reset_token": reset_token,
            "message": "Reset token generated (expires in 15 minutes)"
        }
    
    def reset_password(self, reset_token: str, new_password: str) -> dict:
        """Reset password using a valid reset token."""
        if reset_token not in self.reset_tokens:
            return {"error": "Invalid or expired reset token"}
        
        token_data = self.reset_tokens[reset_token]
        expires_at = datetime.fromisoformat(token_data["expires_at"])
        
        if datetime.now() > expires_at:
            del self.reset_tokens[reset_token]
            return {"error": "Reset token has expired"}
        
        username = token_data["username"]
        new_hash = self.hash_password(new_password)
        self.users[username]["password_hash"] = new_hash
        del self.reset_tokens[reset_token]
        
        print(f"[OK] Password reset successful for '{username}'")
        return {"success": True, "message": "Password reset successfully"}
    
    # ==================== HELPER METHODS ====================
    
    def get_totp_code(self, username: str) -> str:
        """Get current TOTP code for a user (for testing purposes)."""
        if username not in self.users:
            return None
        totp = pyotp.TOTP(self.users[username]["totp_secret"])
        return totp.now()
    
    def get_private_key(self):
        """Get private key for cryptographic operations."""
        return self.private_key
    
    def get_public_key(self):
        """Get public key for cryptographic operations."""
        return self.public_key

