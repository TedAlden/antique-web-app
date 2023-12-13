from models import insert_user
from helpers import generate_salt, hash_password
from pyotp import random_base32
import argparse

parser = argparse.ArgumentParser(
    description="Create an admin account with a given username and password")

parser.add_argument("email", action="store", help="Admin account email")
parser.add_argument("password", action="store", help="Admin account password")


def create_admin_account(email, password, name="Admin", phone="1234"):
    salt = generate_salt()
    hashed = hash_password(password, salt)
    twofa_secret = random_base32()
    try:
        insert_user(name, hashed, salt, email, phone, twofa_secret, True, True)
    except Exception as e:
        print("Error creating admin account:", e)


if __name__ == "__main__":
    args = parser.parse_args()    
    create_admin_account(args.email, args.password)
    
    print("Successfully created admin account.")
    print(f"Email: {args.email}")
    print(f"Password: {args.password}")
