"""
Digital signatures module.
Implements RSA-based digital signatures.
"""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


class DigitalSignatures:
    """
    Digital signatures using RSA.
    
    Digital signatures prove:
    1. Data came from the owner of the private key
    2. Data hasn't been modified
    """
    
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
    
    def sign(self, data: str) -> bytes:
        """
        Create a digital signature using RSA private key.
        
        How it works:
        1. Hash the data
        2. Encrypt the hash with private key (this is the signature)
        3. Anyone can verify by decrypting with public key and comparing hashes
        """
        data_bytes = data.encode('utf-8')
        
        signature = self.private_key.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def verify(self, data: str, signature: bytes) -> bool:
        """Verify a digital signature using public key."""
        data_bytes = data.encode('utf-8')
        
        try:
            self.public_key.verify(
                signature,
                data_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

