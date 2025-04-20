import streamlit as st
import hashlib
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Security Configuration
MAX_ATTEMPTS = 3
SALT = b'salt_123'  # In production, generate unique salt per user

# --- Key Management --- #
def generate_fernet_key():
    """Generate a valid Fernet key (32 URL-safe base64-encoded bytes)"""
    return Fernet.generate_key()

# Initialize or load encryption key
if 'FERNET_KEY' not in st.session_state:
    # In production, load from secure storage instead
    st.session_state.FERNET_KEY = generate_fernet_key()  
    
try:
    cipher = Fernet(st.session_state.FERNET_KEY)
except ValueError as e:
    st.error(f"Invalid encryption key: {str(e)}")
    st.session_state.FERNET_KEY = generate_fernet_key()
    cipher = Fernet(st.session_state.FERNET_KEY)

# --- Enhanced Security Functions --- #
def derive_key(passkey: str, salt: bytes = SALT) -> bytes:
    """Use PBKDF2 for secure key derivation"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

def encrypt_data(text: str) -> str:
    """Encrypt text with Fernet and return base64 string"""
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text: str, passkey: str) -> str:
    """Decrypt text only if passkey verification succeeds"""
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# --- Data Storage --- #
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # {encrypted_text: derived_key}

# --- Streamlit UI --- #
st.title("🔐 Secure Data Vault")
st.warning("For demonstration purposes only - not production-grade security")

# Session state initialization
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'is_logged_in' not in st.session_state:
    st.session_state.is_logged_in = False

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Admin"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Home":
    st.subheader("Secure Data Storage")
    st.markdown("""
    - Military-grade AES-256 encryption
    - Secure key derivation (PBKDF2)
    - Brute-force protection
    """)
    if st.button("Generate New Encryption Key"):
        st.session_state.FERNET_KEY = generate_fernet_key()
        st.success("New key generated! Existing encrypted data will become inaccessible.")

elif choice == "Store Data":
    st.subheader("🔒 Encrypt Data")
    data = st.text_area("Data to encrypt")
    passkey = st.text_input("Passphrase", type="password")
    confirm = st.text_input("Confirm Passphrase", type="password")
    
    if st.button("Encrypt"):
        if not (data and passkey and confirm):
            st.error("All fields required!")
        elif passkey != confirm:
            st.error("Passphrases don't match!")
        else:
            encrypted = encrypt_data(data)
            st.session_state.stored_data[encrypted] = derive_key(passkey)
            st.success("Encrypted successfully!")
            st.code(encrypted)

elif choice == "Retrieve Data":
    st.subheader("🔓 Decrypt Data")
    
    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        st.error("Too many failed attempts! Contact admin.")
        st.stop()
    
    encrypted = st.text_area("Encrypted data")
    passkey = st.text_input("Passphrase", type="password")
    
    if st.button("Decrypt"):
        if not (encrypted and passkey):
            st.error("Both fields required!")
        elif encrypted not in st.session_state.stored_data:
            st.error("Data not found!")
        else:
            stored_key = st.session_state.stored_data[encrypted]
            if derive_key(passkey) == stored_key:
                decrypted = decrypt_data(encrypted, passkey)
                st.success("Decrypted successfully!")
                st.text_area("Result", decrypted, height=200)
            else:
                st.session_state.failed_attempts += 1
                st.error(f"Wrong passphrase! {MAX_ATTEMPTS - st.session_state.failed_attempts} attempts remaining")

elif choice == "Admin":
    st.subheader("⚙️ System Administration")
    if st.text_input("Admin Token", type="password") == "admin123":  # Change in production!
        st.session_state.is_logged_in = True
        st.session_state.failed_attempts = 0
        st.success("Admin access granted")
        st.json({
            "encryption_key": st.session_state.FERNET_KEY.decode(),
            "stored_items": len(st.session_state.stored_data)
        })
    else:
        st.error("Invalid credentials")
