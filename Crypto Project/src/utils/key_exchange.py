"""
Key exchange utilities.
"""

from cryptography.hazmat.primitives import serialization


def get_public_key_pem(public_key) -> str:
    """
    Get public key in PEM format for key exchange.
    
    In real Diffie-Hellman:
    1. Alice and Bob each generate a key pair
    2. They exchange public keys
    3. They compute shared secret using their private key + other's public key
    4. Both get the same shared secret without transmitting it!
    """
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_pem.decode('utf-8')

