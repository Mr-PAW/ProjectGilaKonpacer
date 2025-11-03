import os
import hashlib
import binascii

# cipher buat password hash pake scrypt
def hash_password(password: str) -> tuple[str, str]:
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return binascii.hexlify(salt).decode(), binascii.hexlify(key).decode()

def verify_password(password: str, salt_hex: str, key_hex: str) -> bool:
    salt = binascii.unhexlify(salt_hex)
    key = binascii.unhexlify(key_hex)
    new = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return new == key

# buat hasing gambar (sha256)
def image_hash_bytes(path: str) -> str:
    try:
        with open(path, 'rb') as f:
            b = f.read()
        return hashlib.sha256(b).hexdigest()
    except Exception:
        return ''