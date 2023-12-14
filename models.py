import sqlite3


DATABASE_NAME = "database.db"


def insert_user(name, hashed_password, salt, email, phone, twofa_secret, is_verified=False, is_admin=False):
    """Insert a user into the database.
    
    By default, accounts are unverified and non-admin.

    Args:
        name:
            The account user's name.
        hashed_password:
            The account user's password stored as a hash after being salted.
        salt:
            The salt used to hash the password.
        email:
            The account user's email.
        phone:
            The account user's phone number.
        twofa_secret:
            The secret used to generate an OTP for two-factor authentication.
        is_verified:
            Is the account email verified.
        is_admin:
            Is the account an administrator account.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("INSERT INTO Users (Email, Name, Phone, Password, Salt, IsVerified, IsAdmin) VALUES (?,?,?,?,?,?,?)", (email, name, phone, hashed_password, salt, is_verified, is_admin))
    cur.execute("INSERT INTO TwoFA (Email, IsEnabled, Secret) VALUES (?,?,?)", (email, False, twofa_secret))
    cur.execute("INSERT INTO SecurityQuestions (Email, IsEnabled, Question1, Answer1, Question2, Answer2, Question3, Answer3) VALUES (?,?,?,?,?,?,?,?)", (email, False, None, None, None, None, None, None))
    cur.execute("INSERT INTO LoginCounter (Email, Attempts) VALUES (?,?)", (email, 0))
    con.commit()
    con.close()


def check_user_exists(email):
    """Check if a user exists with a given email.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM Users WHERE Email LIKE ?", (email,))
    rows = cur.fetchall()
    con.commit()
    con.close()
    return len(rows) > 0


def check_user_admin(email):
    """Check if a user account is an adminstrator account.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM Users WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return bool(row[6])


def delete_user(email):
    """Delete a user account.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("DELETE FROM Users WHERE Email LIKE ?", (email,))
    cur.execute("DELETE FROM TwoFA WHERE Email LIKE ?", (email,))
    cur.execute("DELETE FROM SecurityQuestions WHERE Email LIKE ?", (email,))
    cur.execute("DELETE FROM LoginCounter WHERE Email LIKE ?", (email,))
    con.commit()
    con.close()


def get_user_name(email):
    """Get the name of a user account.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM Users WHERE email=?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return row[1]


def get_user_2fa_secret(email):
    """Get the two-factor authentication secret of a user account.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM TwoFA WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return row[2]


def get_user_hashed_password(email):
    """Get the hashed password of a user account.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM Users WHERE email=?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return row[3]


def set_user_hashed_password(email, password):
    """Update the hashed password of a user account with a new one.

    Args:
        email:
            The account user's email.
        password:
            The new password hash to update the account with.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("UPDATE Users SET Password = ? WHERE Email LIKE ?", (password, email))
    con.commit()
    con.close()


def get_user_salt(email):
    """Get the password salt of a user account.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM Users WHERE email=?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return row[4]


def get_user_verified(email):
    """Check if a user account has been verified via email.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM Users WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return bool(row[5])


def set_user_verified(email, is_verified):
    """Set the email verification status of a user account.

    Args:
        email:
            The account user's email.
        is_verified:
            Is the account now verified.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("UPDATE Users SET IsVerified = ? WHERE Email LIKE ?", (is_verified, email))
    con.commit()
    con.close()


def get_user_security_questions_enabled(email):
    """Check if a user account has security questions enabled at login.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM SecurityQuestions WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return bool(row[1])


def set_user_security_questions_enabled(email, enabled):
    """Enable or disable security questions for a user account at login.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("UPDATE SecurityQuestions SET IsEnabled = ? WHERE Email LIKE ?", (enabled, email))
    con.commit()
    con.close()
    return


def get_user_security_questions(email):
    """Get the security questions and answers for a user account.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM SecurityQuestions WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return row[2:8]


def set_user_security_questions(email, q1, a1, q2, a2, q3, a3):
    """Update the security questions and answers for a user account.

    Args:
        email:
            The account user's email.
        q1:
            Security question 1.
        a1:
            Answer to security question 1.
        q2:
            Security question 2.
        a2:
            Answer to security question 2.
        q3:
            Security question 3.
        a3:
            Answer to security question 3.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("UPDATE SecurityQuestions SET IsEnabled = True, Question1 = ?, Answer1 = ?, Question2 = ?, Answer2 = ?, Question3 = ?, Answer3 = ? WHERE Email LIKE ?", (q1, a1, q2, a2, q3, a3, email))
    con.commit()
    con.close()
    return


def check_2fa_enabled(email):
    """Check if a user account has two-factor authentication enabled.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM TwoFA WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return bool(row[1])


def set_2fa_enabled(email, enabled):
    """Enable or disable two-factor authentication for a user account.

    Args:
        email:
            The account user's email.
        enabled:
            Is two-factor authentication now enabled.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("UPDATE TwoFA SET IsEnabled = ? WHERE Email LIKE ?", (enabled, email))
    con.commit()
    con.close()


def insert_evaluation(email, description, contact, photo_path):
    """Insert an evaluation into the database.

    Args:
        email:
            The account user's email.
        description:
            Description of the antique that is being requested an evaluation.
        contact:
            Preferred method of contact for the user requesting the evaluation.
        photo_path:
            The path to the image of the antique on the server.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("INSERT INTO EvaluationRequests (Email, Description, Contact, PhotoPath) VALUES (?,?,?,?)", (email, description, contact, photo_path))
    con.commit()
    con.close()


def get_all_evaluations():
    """Get all evaluations.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM EvaluationRequests")
    rows = cur.fetchall()
    con.commit()
    con.close()
    return rows


def get_user_evaluations(email):
    """Get evaluations requested by a specific user account.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM EvaluationRequests WHERE Email LIKE ?", (email,))
    rows = cur.fetchall()
    con.commit()
    con.close()
    return rows


def get_user_login_attempt_count(email):
    """Count how many failed login attempts for a user account.
    
    This is the number of failed login attempts since the last successful
    login.

    Args:
        email:
            The account user's email.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM LoginCounter WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return row[1]


def set_user_login_attempt_count(email, amount):
    """Update the count of failed login attempts for a user account.
    
    This is the number of failed login attempts since the last successful
    login.

    Args:
        email:
            The account user's email.
        amount:
            The amount of failed login attempts.
    """
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("UPDATE LoginCounter SET Attempts = ? WHERE Email LIKE ?", (amount, email))
    con.commit()
    con.close()
