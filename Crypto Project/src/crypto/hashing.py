"""
Hash functions module.
Implements SHA-256 hashing.
"""

import hashlib


class SHA256Hash:
    """
    SHA-256 hash function implementation.
    
    Hash functions are one-way: easy to compute, impossible to reverse.
    They're used for:
    - Verifying data integrity
    - Creating digital fingerprints
    - Password hashing (though bcrypt is better for passwords)
    """
    
    @staticmethod
    def hash(data: str) -> str:
        """
        Hash data using SHA-256.
        
        SHA-256 always produces 256-bit (32-byte) output.
        """
        data_bytes = data.encode('utf-8')
        hash_obj = hashlib.sha256(data_bytes)
        return hash_obj.hexdigest()  # Return as hexadecimal string
    
    @staticmethod
    def simple_demo(data: str) -> str:
        """
        Simplified demonstration of how SHA-256 works.
        
        Real SHA-256 is very complex, but here's the basic idea:
        1. Convert input to binary
        2. Pad to multiple of 512 bits
        3. Process in 512-bit chunks
        4. Apply compression function with constants
        5. Output 256-bit hash
        """
        data_bytes = data.encode('utf-8')
        
        # Initialize hash values (constants in SHA-256)
        h0 = 0x6a09e667
        h1 = 0xbb67ae85
        h2 = 0x3c6ef372
        h3 = 0xa54ff53a
        h4 = 0x510e527f
        h5 = 0x9b05688c
        h6 = 0x1f83d9ab
        h7 = 0x5be0cd19
        
        # For this demo, we use the library
        # Real implementation would do all bitwise operations manually
        hash_obj = hashlib.sha256(data_bytes)
        result = hash_obj.hexdigest()
        
        print(f"  Input: {data}")
        print(f"  SHA-256 Hash: {result}")
        print(f"  (This uses library, but real implementation would do bitwise operations)")
        
        return result

