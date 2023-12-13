from models import insert_user
from helpers import generate_salt, hash_password
from pyotp import random_base32


def create_admin_account():
    username = "admin"
    password = "admin"
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    email = "t.aldentempleman@gmail.com"
    phone = "000"
    twofa_secret = random_base32()
    is_verified = True
    is_admin = True
    
    try:
        insert_user(username, hashed_password, salt, email, phone, twofa_secret, True, True)
    except Exception as e:
        print("Error creating admin account:", e)


if __name__ == "__main__":
    create_admin_account()
