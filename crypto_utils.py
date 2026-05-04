
import os
import base64
import hashlib
import json
from datetime import datetime, timezone, timedelta
from typing import Tuple

import jwt  # PyJWT
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from config import AES_KEY_BYTES, RSA_KEY_BITS, JWT_ALGORITHM, JWT_EXPIRY_SECONDS


def generate_aes_key() -> bytes:
    return os.urandom(AES_KEY_BYTES)


def aes_encrypt(plaintext: str, key: bytes) -> str:
    
    iv = os.urandom(16)
    # PKCS#7-style manual padding to 16-byte blocks
    data = plaintext.encode()
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode()


def aes_decrypt(ciphertext_b64: str, key: bytes) -> str:
    raw = base64.b64decode(ciphertext_b64)
    iv, ciphertext = raw[:16], raw[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS#7 padding
    pad_len = padded[-1]
    return padded[:-pad_len].decode()


def generate_rsa_keypair() -> Tuple[bytes, bytes]:
  
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_BITS,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def rsa_encrypt(data: bytes, public_pem: bytes) -> str:
   
    public_key = serialization.load_pem_public_key(public_pem, backend=default_backend())
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()


def rsa_decrypt(ciphertext_b64: str, private_pem: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(
        private_pem, password=None, backend=default_backend()
    )
    encrypted = base64.b64decode(ciphertext_b64)
    return private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def sign_data(data: str, private_pem: bytes) -> str:
   
    private_key = serialization.load_pem_private_key(
        private_pem, password=None, backend=default_backend()
    )
    signature = private_key.sign(
        data.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(data: str, signature_b64: str, public_pem: bytes) -> bool:
   
    try:
        public_key = serialization.load_pem_public_key(public_pem, backend=default_backend())
        public_key.verify(
            base64.b64decode(signature_b64),
            data.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def generate_jwt(payload: dict, secret: str) -> str:
  
    now = datetime.now(tz=timezone.utc)
    payload = {
        **payload,
        "iat": now,
        "exp": now + timedelta(seconds=JWT_EXPIRY_SECONDS),
    }
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def verify_jwt(token: str, secret: str) -> dict:
    
    return jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])


def sha256_hex(data: str) -> str:
    
    return hashlib.sha256(data.encode()).hexdigest()


def hash_password(password: str) -> str:
  
    salt = "ehr_audit_2026"
    return sha256_hex(salt + password)


def encode_key(key_bytes: bytes) -> str:
  
    return base64.b64encode(key_bytes).decode()


def decode_key(key_b64: str) -> bytes:

    return base64.b64decode(key_b64)
