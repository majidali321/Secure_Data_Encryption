import streamlit as st
import hashlib
import os
import json
import time
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac
from cryptography.fernet import Fernet


DATA_FILE ="secure_data.json"
SALT = b"seccure_salt_value"
LOCKOUT_DURATION = 60

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

def load_data():
    if os.path.exist(DATA_FILE):
        with open(DATA_FILE,"r") as f:
            return json.load(f)
def save_data(data):
    with open(DATA_FILE,"w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key= pbkdf2_hmac("sha256",passkey.encode(),SALT,100000)
def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256',password.encode(), SALT,100000).hex()
def encrypt_text(text,key):
    cipher  = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()
def decrypt_text(encrypt_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None
store_data = load_data()

st.title("Store Data Encryption System")
menu =["Home","Register","Login","Store Data","Retrieve Data"]
choice = st.sidebar.selectbox("Navigation",menu)

if choice == "Home":
    st.subheader("Welocome to My Data Encryption System using Streamlit !")
    st.markdown("This Data Encrypted System is a secure web application built using Streamlit that allows users to encrypt and decrypt sensitive information with ease. By leveraging Python’s cryptography library, the app ensures confidentiality through symmetric encryption methods like AES or Fernet. Users can input plain text or upload files to be encrypted, then decrypt them later using a secret key—all through a clean and interactive interface. Designed for simplicity and security, the system is ideal for securely sharing information or demonstrating the principles of modern data encryption.")
elif choice == "Register":
    st.subheader("Register New User")
    username = st.text_input("choose UserName")
    password = st.text_input("Choose Password",type ="password")
    if st.button("Register"):
        if username and password:
            if username in store_data:
                st.warning("User already exist")
            else:
                store_data[username] = {
                    "password":hash_password(password),
                    "data" :[]
                }
                save_data(store_data)
                st.success("Registration Successfully")
        else:
            st.error("Both fields are required")
elif choice == "Login":
        st.subheader("user login")
        if time.time() < st.session_state.lockout_time:
            remaining = int(st.session_state.lockout_time - time.time())
            st.error("too many failds attempts please wait {remaining} secconds ")
            st.stop()
        username  = st.text_input("Username")
        password = st.text_input("password",type="password")
        if st.button("Login"):
            if username in store_data and store_data[username]["Password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_sttempts = 0
                st.success(f"Welcome {username}")
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"invalid credentials attempts left {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("too many failed attempts.locked for 60 seconds")
                    st.stop()
elif choice == "Store Data":
        if not st.session_state.authenticated_user:
            st.warning("plz login first")
        else:
            st.subheader("Store encrypted data")
            data = st.text_area("Enter data to encrypt")
            passkey = st.text_input("encryption key(passphrase)" ,type="password")

            if st.button("Encrypt and save"):
                if data and passkey:
                    encrypted = encrypt_text(data , passkey)
                    store_data[st.session_state.authenticated_user]["data"].append(encrypted)
                    save_data(store_data)
                    st.success("Data encrypted and store successfully ")
                else:
                    st.error("All fields are require to fill")
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("plz login first")
    else:
        st.subheader("Data Retrieved")
        user_data = store_data.get(st.session_state.authenticated_user{}).get("data",[])
        if not user_data:
            st.info("no data found")
        else:
            st.write("Encrypted data entries")
            for i , item in enumerate(user_data):
                st.code(item,language="text")
            
            encrypted_input = st.text_area("enter encrypted text")
            passkey = st.text_input("Enter passkey too decrypt",type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input,passkey)
                if result:
                    st.success(f"Decrypt {result}")
                else:
                    st.error("Invalid passkey or curropted data")
