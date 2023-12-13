from hashlib import sha256

import uuid


def generate_salt() -> str:
    return uuid.uuid4().hex


def hash_password(password: str, salt: str) -> str:
    h = sha256(password.encode('utf-8') + salt.encode('utf-8'))
    return h.hexdigest()
