"""
Secure random number generation utilities.
"""

import secrets


def generate_secure_random(length: int = 32) -> str:
    """
    Generate cryptographically secure random bytes.
    
    This is important for:
    - Generating tokens
    - Creating salts
    - Generating encryption keys
    
    We use secrets module which uses OS's secure random generator.
    """
    return secrets.token_hex(length)

