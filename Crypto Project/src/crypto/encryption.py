"""
Encryption modules for symmetric (AES) and asymmetric (RSA) encryption.
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class AESEncryption:
    """
    AES-256 symmetric encryption.
    
    Symmetric encryption means same key is used to encrypt and decrypt.
    AES-256 is very secure and widely used.
    """
    
    @staticmethod
    def encrypt(plaintext: str, password: str) -> tuple:
        """
        Encrypt data using AES-256.
        
        Steps:
        1. Generate a random salt
        2. Derive encryption key from password using PBKDF2
        3. Generate random IV (Initialization Vector)
        4. Encrypt data with AES-256 in CBC mode
        """
        plaintext_bytes = plaintext.encode('utf-8')
        password_bytes = password.encode('utf-8')
        
        # Generate random salt
        salt = os.urandom(16)
        
        # Derive encryption key from password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits for AES-256
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password_bytes)
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Create cipher and encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad plaintext to be multiple of 16 bytes
        pad_length = 16 - (len(plaintext_bytes) % 16)
        padded = plaintext_bytes + bytes([pad_length] * pad_length)
        
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        
        return (ciphertext, salt, iv)
    
    @staticmethod
    def decrypt(ciphertext: bytes, password: str, salt: bytes, iv: bytes) -> str:
        """Decrypt data encrypted with AES-256."""
        password_bytes = password.encode('utf-8')
        
        # Derive same key from password and salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password_bytes)
        
        # Create cipher and decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        pad_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-pad_length]
        
        return plaintext.decode('utf-8')


class RSAEncryption:
    """
    RSA asymmetric encryption.
    
    Asymmetric encryption uses two keys:
    - Public key: anyone can use to encrypt
    - Private key: only you can use to decrypt
    """
    
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key
    
    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt data using RSA public key."""
        plaintext_bytes = plaintext.encode('utf-8')
        
        if len(plaintext_bytes) > 214:
            return b"Data too large for RSA encryption"
        
        ciphertext = self.public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt data encrypted with RSA using private key."""
        plaintext_bytes = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext_bytes.decode('utf-8')

