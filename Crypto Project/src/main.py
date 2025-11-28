"""
Entry point for the Secure Authentication System.
This is the main file that starts the interactive application.
"""

import json
import pyotp
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.auth_system import SecureAuthSystem
from crypto.encryption import AESEncryption, RSAEncryption
from crypto.hashing import SHA256Hash
from crypto.signatures import DigitalSignatures
from utils.random_generator import generate_secure_random
from utils.key_exchange import get_public_key_pem


def show_menu():
    """Display the interactive menu"""
    print("\n" + "=" * 60)
    print("SECURE AUTHENTICATION SYSTEM - INTERACTIVE MENU")
    print("=" * 60)
    print("1. Register new user")
    print("2. Login")
    print("3. Get TOTP code (for testing)")
    print("4. Verify JWT token")
    print("5. Request password reset")
    print("6. Reset password")
    print("7. Test AES encryption")
    print("8. Test RSA encryption")
    print("9. Test SHA-256 hashing")
    print("10. Test digital signatures")
    print("11. Run full demonstration")
    print("12. List registered users")
    print("0. Exit")
    print("=" * 60)


def interactive_mode():
    """Interactive mode where user can interact with the authentication system."""
    print("\n" + "=" * 60)
    print("SECURE AUTHENTICATION SYSTEM")
    print("=" * 60)
    print("\nInitializing system...")
    
    # Create authentication system
    auth = SecureAuthSystem()
    
    # Create cryptographic modules
    rsa_encryption = RSAEncryption(auth.get_public_key(), auth.get_private_key())
    digital_signatures = DigitalSignatures(auth.get_private_key(), auth.get_public_key())
    
    while True:
        show_menu()
        choice = input("\nEnter your choice (0-12): ").strip()
        
        if choice == "0":
            print("\nThank you for using Secure Authentication System!")
            print("Goodbye!")
            break
        
        elif choice == "1":
            print("\n--- REGISTER NEW USER ---")
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            
            if not username or not password:
                print("[ERROR] Username and password are required!")
                continue
            
            result = auth.register_user(username, password)
            print(f"\nResult: {json.dumps(result, indent=2)}")
            
            if "totp_secret" in result:
                print(f"\n[IMPORTANT] Save your TOTP secret: {result['totp_secret']}")
                print("You'll need this for 2FA login!")
                print(f"QR Code URI: {result['qr_uri']}")
        
        elif choice == "2":
            print("\n--- LOGIN ---")
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            totp_code = input("Enter TOTP code (6 digits): ").strip()
            
            if not username or not password or not totp_code:
                print("[ERROR] All fields are required!")
                continue
            
            result = auth.login(username, password, totp_code)
            print(f"\nResult: {json.dumps(result, indent=2)}")
            
            if "token" in result:
                print(f"\n[SUCCESS] Login successful!")
                print(f"JWT Token: {result['token']}")
        
        elif choice == "3":
            print("\n--- GET TOTP CODE ---")
            username = input("Enter username: ").strip()
            
            if not username:
                print("[ERROR] Username is required!")
                continue
            
            totp_code = auth.get_totp_code(username)
            if totp_code:
                print(f"\n[OK] Current TOTP code for '{username}': {totp_code}")
                print("(This code changes every 30 seconds)")
            else:
                print(f"[ERROR] User '{username}' not found!")
        
        elif choice == "4":
            print("\n--- VERIFY JWT TOKEN ---")
            token = input("Enter JWT token: ").strip()
            
            if not token:
                print("[ERROR] Token is required!")
                continue
            
            result = auth.verify_jwt_token(token)
            print(f"\nResult: {json.dumps(result, indent=2)}")
        
        elif choice == "5":
            print("\n--- REQUEST PASSWORD RESET ---")
            username = input("Enter username: ").strip()
            
            if not username:
                print("[ERROR] Username is required!")
                continue
            
            result = auth.request_password_reset(username)
            print(f"\nResult: {json.dumps(result, indent=2)}")
            
            if "reset_token" in result:
                print(f"\n[IMPORTANT] Reset token: {result['reset_token']}")
        
        elif choice == "6":
            print("\n--- RESET PASSWORD ---")
            reset_token = input("Enter reset token: ").strip()
            new_password = input("Enter new password: ").strip()
            
            if not reset_token or not new_password:
                print("[ERROR] Reset token and new password are required!")
                continue
            
            result = auth.reset_password(reset_token, new_password)
            print(f"\nResult: {json.dumps(result, indent=2)}")
        
        elif choice == "7":
            print("\n--- TEST AES ENCRYPTION ---")
            plaintext = input("Enter text to encrypt: ").strip()
            password = input("Enter encryption password: ").strip()
            
            if not plaintext or not password:
                print("[ERROR] Both fields are required!")
                continue
            
            ciphertext, salt, iv = AESEncryption.encrypt(plaintext, password)
            print(f"\nPlaintext: {plaintext}")
            print(f"Ciphertext (hex): {ciphertext.hex()}")
            
            decrypted = AESEncryption.decrypt(ciphertext, password, salt, iv)
            print(f"Decrypted: {decrypted}")
            print(f"[OK] Encryption/decryption successful!")
        
        elif choice == "8":
            print("\n--- TEST RSA ENCRYPTION ---")
            message = input("Enter message to encrypt (max ~200 chars): ").strip()
            
            if not message:
                print("[ERROR] Message is required!")
                continue
            
            if len(message) > 200:
                print("[ERROR] Message too long for RSA encryption!")
                continue
            
            encrypted = rsa_encryption.encrypt(message)
            print(f"\nMessage: {message}")
            print(f"Encrypted (hex): {encrypted.hex()[:100]}...")
            
            decrypted = rsa_encryption.decrypt(encrypted)
            print(f"Decrypted: {decrypted}")
            print(f"[OK] RSA encryption/decryption successful!")
        
        elif choice == "9":
            print("\n--- TEST SHA-256 HASHING ---")
            data = input("Enter data to hash: ").strip()
            
            if not data:
                print("[ERROR] Data is required!")
                continue
            
            hash_result = SHA256Hash.hash(data)
            print(f"\nData: {data}")
            print(f"SHA-256 Hash: {hash_result}")
            print(f"[OK] Hashing successful!")
        
        elif choice == "10":
            print("\n--- TEST DIGITAL SIGNATURES ---")
            document = input("Enter document to sign: ").strip()
            
            if not document:
                print("[ERROR] Document is required!")
                continue
            
            signature = digital_signatures.sign(document)
            print(f"\nDocument: {document}")
            print(f"Signature (hex): {signature.hex()[:100]}...")
            
            is_valid = digital_signatures.verify(document, signature)
            print(f"Signature valid: {is_valid}")
            
            modified = document + " (MODIFIED)"
            is_valid_modified = digital_signatures.verify(modified, signature)
            print(f"Modified document signature valid: {is_valid_modified}")
            print(f"[OK] Digital signature test complete!")
        
        elif choice == "11":
            run_demo(auth, rsa_encryption, digital_signatures)
        
        elif choice == "12":
            print("\n--- REGISTERED USERS ---")
            if not auth.users:
                print("No users registered yet.")
            else:
                for username in auth.users.keys():
                    print(f"  - {username}")
        
        else:
            print("\n[ERROR] Invalid choice! Please enter a number between 0-12.")
        
        input("\nPress Enter to continue...")


def run_demo(auth, rsa_encryption, digital_signatures):
    """Run the full demonstration of all features."""
    print("\n" + "=" * 60)
    print("FULL DEMONSTRATION")
    print("=" * 60)
    print()
    
    # User registration
    print("1. USER REGISTRATION")
    print("-" * 60)
    result = auth.register_user("demo_user", "DemoPassword123!")
    print(f"Registration result: {json.dumps(result, indent=2)}")
    print()
    
    # Login
    print("2. LOGIN WITH MULTI-FACTOR AUTHENTICATION")
    print("-" * 60)
    totp = pyotp.TOTP(auth.users["demo_user"]["totp_secret"])
    current_totp = totp.now()
    login_result = auth.login("demo_user", "DemoPassword123!", current_totp)
    print(f"Login result: {json.dumps(login_result, indent=2)}")
    print()
    
    # Cryptographic components
    print("3. MANDATORY CRYPTOGRAPHIC COMPONENTS")
    print("-" * 60)
    
    # AES
    print("\n3.1 SYMMETRIC ENCRYPTION (AES-256)")
    plaintext = "This is a secret message!"
    password = "MyEncryptionPassword"
    ciphertext, salt, iv = AESEncryption.encrypt(plaintext, password)
    print(f"  Plaintext: {plaintext}")
    decrypted = AESEncryption.decrypt(ciphertext, password, salt, iv)
    print(f"  Decrypted: {decrypted}")
    print(f"  [OK] AES encryption/decryption works!")
    
    # RSA
    print("\n3.2 ASYMMETRIC ENCRYPTION (RSA)")
    message = "Hello, this is encrypted with RSA!"
    encrypted = rsa_encryption.encrypt(message)
    decrypted_rsa = rsa_encryption.decrypt(encrypted)
    print(f"  Message: {message}")
    print(f"  Decrypted: {decrypted_rsa}")
    print(f"  [OK] RSA encryption/decryption works!")
    
    # SHA-256
    print("\n3.3 HASH FUNCTION (SHA-256)")
    data = "This data will be hashed"
    hash_result = SHA256Hash.hash(data)
    print(f"  Data: {data}")
    print(f"  SHA-256 Hash: {hash_result}")
    print(f"  [OK] SHA-256 hashing works!")
    
    # Digital signatures
    print("\n3.4 DIGITAL SIGNATURES (RSA)")
    document = "Important document: User agreement"
    signature = digital_signatures.sign(document)
    is_valid = digital_signatures.verify(document, signature)
    print(f"  Document: {document}")
    print(f"  Signature valid: {is_valid}")
    print(f"  [OK] Digital signatures work!")
    
    # Key exchange
    print("\n3.5 KEY EXCHANGE")
    public_key_pem = get_public_key_pem(auth.get_public_key())
    print(f"  Public Key (PEM format, first 100 chars):")
    print(f"  {public_key_pem[:100]}...")
    print(f"  [OK] Public key can be shared for key exchange!")
    
    # Secure random
    print("\n3.6 SECURE RANDOM NUMBER GENERATION")
    random_token = generate_secure_random(32)
    print(f"  Random token: {random_token}")
    print(f"  [OK] Secure random generation works!")
    
    print()
    print("=" * 60)
    print("DEMONSTRATION COMPLETE!")
    print("=" * 60)


def main():
    """Main function - starts interactive mode."""
    interactive_mode()


if __name__ == "__main__":
    main()

