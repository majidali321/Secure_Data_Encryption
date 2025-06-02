import streamlit as st
import hashlib
import os
import json
import time
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac
from cryptography.fernet import Fernet

# Constants
DATA_FILE = "secure_data.json"
SALT = b"seccure_salt_value"
LOCKOUT_DURATION = 60

# Session state initialization
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Load data from JSON file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save data to JSON file
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Generate encryption key from passphrase
def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

# Hash password
def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

# Encrypt text
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

# Decrypt text
def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Load stored data
store_data = load_data()

# UI
st.title("Store Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("Welcome to My Data Encryption System using Streamlit!")
    st.markdown("""
        This Data Encrypted System is a secure web application built using Streamlit that allows users to encrypt and decrypt sensitive information with ease. 
        By leveraging Python’s cryptography library, the app ensures confidentiality through symmetric encryption methods like Fernet.
        
        Users can input plain text to be encrypted, then decrypt them later using a secret key—all through a clean and interactive interface.
    """)

elif choice == "Register":
    st.subheader("Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in store_data:
                st.warning("User already exists.")
            else:
                store_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(store_data)
                st.success("Registration successful.")
        else:
            st.error("Both fields are required.")

elif choice == "Login":
    st.subheader("User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in store_data and store_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"Invalid credentials. Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("Too many failed attempts. Locked for 60 seconds.")
                st.stop()

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first.")
    else:
        st.subheader("Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                store_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(store_data)
                st.success("Data encrypted and stored successfully.")
            else:
                st.error("All fields are required.")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first.")
    else:
        st.subheader("Retrieve Encrypted Data")
        user_data = store_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data found.")
        else:
            st.write("Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("Enter encrypted text to decrypt")
            passkey = st.text_input("Enter passkey to decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"Decrypted: {result}")
                else:
                    st.error("Invalid passkey or corrupted data.")
