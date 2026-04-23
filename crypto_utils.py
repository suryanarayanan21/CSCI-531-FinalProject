"""
crypto_utils.py
---------------
Cryptographic primitives for the EHR Blockchain Audit System.

Provides:
  - AES-256-CBC  : symmetric encryption of audit records (privacy at rest)
  - RSA-2048     : asymmetric key pairs for users; encrypts per-patient AES keys
  - PKCS1v15/SHA-256 signatures : proves integrity and authenticity of records
  - JWT (HS256)  : stateless authentication tokens
  - SHA-256 hashing helpers
"""

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


# ── AES-256-CBC ──────────────────────────────────────────────────────────────

def generate_aes_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return os.urandom(AES_KEY_BYTES)


def aes_encrypt(plaintext: str, key: bytes) -> str:
    """
    Encrypt *plaintext* with AES-256-CBC.

    Returns a base64-encoded string containing  IV (16 B) || ciphertext,
    suitable for storing in the blockchain record.
    """
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
    """Decrypt a base64-encoded IV||ciphertext blob and return plaintext."""
    raw = base64.b64decode(ciphertext_b64)
    iv, ciphertext = raw[:16], raw[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS#7 padding
    pad_len = padded[-1]
    return padded[:-pad_len].decode()


# ── RSA-2048 ─────────────────────────────────────────────────────────────────

def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a fresh RSA-2048 key pair.

    Returns (private_pem, public_pem) as PEM-encoded bytes.
    """
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
    """
    Encrypt *data* with an RSA public key (OAEP / SHA-256).

    Used to wrap per-patient AES keys so only the key-holder can decrypt them.
    Returns base64-encoded ciphertext.
    """
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
    """Decrypt RSA-OAEP ciphertext; returns raw bytes."""
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


# ── Digital Signatures ───────────────────────────────────────────────────────

def sign_data(data: str, private_pem: bytes) -> str:
    """
    Sign *data* (string) with an RSA private key using PKCS1v15 / SHA-256.

    Returns base64-encoded signature.  Used to authenticate audit records so
    the submitting EHR system can be held accountable.
    """
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
    """
    Verify a PKCS1v15 / SHA-256 signature.

    Returns True if the signature is valid, False otherwise.
    """
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


# ── JWT ──────────────────────────────────────────────────────────────────────

def generate_jwt(payload: dict, secret: str) -> str:
    """
    Issue a signed JWT with an expiry of JWT_EXPIRY_SECONDS.

    *payload* should include at minimum {'username': ..., 'role': ...}.
    """
    now = datetime.now(tz=timezone.utc)
    payload = {
        **payload,
        "iat": now,
        "exp": now + timedelta(seconds=JWT_EXPIRY_SECONDS),
    }
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def verify_jwt(token: str, secret: str) -> dict:
    """
    Verify and decode a JWT.

    Returns the decoded payload dict, or raises jwt.InvalidTokenError on failure.
    """
    return jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])


# ── Hashing ──────────────────────────────────────────────────────────────────

def sha256_hex(data: str) -> str:
    """Return the SHA-256 hex digest of *data* (used internally by blockchain)."""
    return hashlib.sha256(data.encode()).hexdigest()


def hash_password(password: str) -> str:
    """
    One-way hash a password with SHA-256 + a fixed salt.
    Production systems would use bcrypt/argon2; SHA-256 suffices for this demo.
    """
    salt = "ehr_audit_2026"
    return sha256_hex(salt + password)


# ── Utility ───────────────────────────────────────────────────────────────────

def encode_key(key_bytes: bytes) -> str:
    """Base64-encode raw key bytes for JSON transport."""
    return base64.b64encode(key_bytes).decode()


def decode_key(key_b64: str) -> bytes:
    """Decode a base64-encoded key back to raw bytes."""
    return base64.b64decode(key_b64)
