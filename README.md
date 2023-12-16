# Antique Web App

> A simple antique dealing web application focusing on implementation of cybersecurity features. Using Python3, Flask, SQLite, HTML/CSS/JS.

## Table of Contents
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Requirements](#requirements)
- [Setup](#setup)
- [Security features](#security-features)
    - [Password security](#password-security)
    - [Authentication](#authentication)
    - [Vulnerability protection](#vulnerability-protection)


## Introduction

This project was undertaken as the coursework assessment for the *Introduction to Computer Security* module during my third year at University.

**Project brief**: "In this part of the coursework, you will develop a secure web application for a local antique dealer named Lovejoy. Lovejoy wants a minimum viable product allowing customers to register and then request evaluations of potential antique objects. Lovejoy has many rivals in the antique business who may sometimes resort to underhand tactics and so is very concerned about the security of the application."

## Requirements

- Python version >= `3.11.0`
- Google ReCaptcha account.
- Email account for server to use when emailing users.

## Setup

Setup instructions should apply to all platforms (Windows, Linux, and macOS).

Make sure you have the [required](#requirements) version of Python installed.

1. Clone the repository.

    ```
    git clone https://github.com/TedAlden/antique-web-app
    cd antique-web-app
    ```

2. Install the required Python packages using pip.

    ```
    python3 -m pip install -r requirements.txt
    ```

3. Construct a database using the schema file.

    ```
    sqlite3 database.db < schema.sql
    ```

4. Optional: Create an admin account for the web application and note the email and password. These details can be changed as necessary within the script.

    ```
    python3 create_admin_account.py [EMAIL] [PASSWORD]
    ```

5. Create a `.env` file to configure application settings by copying the `.sample-env`.

    ```bash
    cp .sample-env .env
    ```

6. Configure a secret key for the Flask application in the `.env` file.

    ```
    SECRET_KEY=
    ```

    A secret key can be randomly generated using the Python terminal command:

    ```bash
    python3 -c 'import secrets; print(secrets.token_hex())'
    ```

7. Configure Google ReCaptcha keys in the `.env` file.

    ```
    RECAPTCHA_PUBLIC_KEY=
    RECAPTCHA_PRIVATE_KEY=
    ```

8. Configure mail server options in the `.env` file. The server and port are configured for Gmail by default but this can be changed as necessary.

    ```bash
    MAIL_SERVER=smtp.googlemail.com
    MAIL_PORT=587
    MAIL_USE_TLS=True
    MAIL_USERNAME=
    MAIL_PASSWORD=
    ```

9. Run the application using Flask on port `5000`. You can change the port if necessary.

    ```
    flask run --port 5000
    ```

10. Visit the website via the address output in the terminal when running the application. This will probably be `127.0.0.1:5000`.

## Security features

The goal of this coursework project was to deliver only a 'minimum-viable product' for an antique dealer. The focus was instead on the security features of the web application, as detailed below.

### Password security

- "Strong" passwords required
- Passwords are hashed in the database
- Salted password hashes
- Password recovery feature

### Authentication

- User account management (Register, login, change password or email, delete account)
- Email verification required for registration
- 2 factor authentication via Google Authenticator
- Security questions
- Captchas

### Vulnerability protection

- SQL injection
- XSS
- CSRF
- File upload
- Brute force attack (Limited number of login attempts)
- Botnet attack (Captcha required for login or signup)
- Dictionary attack (strong passwords are required)
- Rainbow table attack (Passwords are salted)
