# Antique Web App

> A simple antique dealing web application focusing on implementation of cybersecurity features. Using Python3, Flask, SQLite, HTML/CSS/JS.

## Table of Contents
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Requirements](#requirements)
- [Setup](#setup)
- [Security features](#security-features)
    - [Password policies](#password-policies)
    - [Authentication](#authentication)
    - [Vulnerability and common attack coverage](#vulnerability-and-common-attack-coverage)


## Introduction

This project was undertaken as the coursework assessment for the *Introduction to Computer Security* module during my third year at University.

**Project brief**: "In this part of the coursework, you will develop a secure web application for a local antique dealer named Lovejoy. Lovejoy wants a minimum viable product allowing customers to register and then request evaluations of potential antique objects. Lovejoy has many rivals in the antique business who may sometimes resort to underhand tactics and so is very concerned about the security of the application."

## Requirements

- Python version >= `3.11.0`

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

3. Run the application using Flask on port 5000. You can change the port if necessary.

    ```
    flask run --port 5000
    ```

4. Visit the website via the address output in the terminal after the previous command. This will probably be `127.0.0.1:5000`.

## Security features

The goal of this coursework project was to deliver only a 'minimum-viable product' for an antique dealer. The focus was instead on the security features of the web application, as detailed below.

### Password policies

- Password entropy
- Encrypted storage of passwords
- Salted passwords
- Security questions
- Password recovery

### Authentication

- User identity management (Registration, Login, Change password, Change email, Delete account)
- Email verification for registration
- 2 factor authentication for login using PIN (via Email or Google Authenticator)

### Vulnerability and common attack coverage

- SQL injection
- XSS
- CSRF
- File upload
- Brute force attack (Limit number of login attempts)
- Botnet attack (Captcha required for login or signup)
- Dictionary attack (Require stronger passwords)
- Rainbow table attack (Salted passwords)
