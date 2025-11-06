import os, hashlib
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERS = 200_000
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32  # AES-256

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, plaintext, None)  # ciphertext || tag
    return salt + nonce + ct

def decrypt_bytes(enc: bytes, password: str) -> bytes:
    salt = enc[:SALT_LEN]
    nonce = enc[SALT_LEN:SALT_LEN+NONCE_LEN]
    ct = enc[SALT_LEN+NONCE_LEN:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def encrypt_file(path: str, password: str) -> tuple[bytes, str]:
    with open(path, 'rb') as f:
        data = f.read()
    digest = sha256_hex(data)  # hash of plaintext
    enc = encrypt_bytes(data, password)
    return enc, digest

def decrypt_to_bytes(enc_bytes: bytes, password: str) -> bytes:
    return decrypt_bytes(enc_bytes, password)
