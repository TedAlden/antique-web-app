import sqlite3


DATABASE_NAME = "database.db"


def init_db():
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    with open('schema.sql') as fp:
        cur.executescript(fp.read())


def insert_user(name, hashed_password, salt, email, phone, twofa_secret, is_verified=False, is_admin=False):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("INSERT INTO Users (Email, Name, Phone, Password, Salt, IsVerified, IsAdmin) VALUES (?,?,?,?,?,?,?)", (email, name, phone, hashed_password, salt, is_verified, is_admin))
    cur.execute("INSERT INTO TwoFA (Email, IsEnabled, Secret) VALUES (?,?,?)", (email, False, twofa_secret))
    cur.execute("INSERT INTO SecurityQuestions (Email, IsEnabled, Question1, Answer1, Question2, Answer2, Question3, Answer3) VALUES (?,?,?,?,?,?,?,?)", (email, False, None, None, None, None, None, None))
    cur.execute("INSERT INTO LoginCounter (Email, Attempts) VALUES (?,?)", (email, 0))
    con.commit()
    con.close()


def check_user_exists(email):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM Users WHERE Email LIKE ?", (email,))
    rows = cur.fetchall()
    con.commit()
    con.close()
    return len(rows) > 0


def check_user_admin(email):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM Users WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return bool(row[6])


def delete_user(email):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("DELETE FROM Users WHERE Email LIKE ?", (email,))
    cur.execute("DELETE FROM TwoFA WHERE Email LIKE ?", (email,))
    cur.execute("DELETE FROM SecurityQuestions WHERE Email LIKE ?", (email,))
    cur.execute("DELETE FROM LoginCounter WHERE Email LIKE ?", (email,))
    con.commit()
    con.close()


def get_user_name(email):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM Users WHERE email=?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return row[1]


def get_user_2fa_secret(email):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM TwoFA WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return row[2]


def get_user_hashed_password(email):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM Users WHERE email=?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return row[3]


def set_user_hashed_password(email, password):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("UPDATE Users SET Password = ? WHERE Email LIKE ?", (password, email))
    con.commit()
    con.close()


def get_user_salt(email):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM Users WHERE email=?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return row[4]


def get_user_verified(email):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM Users WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return bool(row[5])


def set_user_verified(email, is_verified):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("UPDATE Users SET IsVerified = ? WHERE Email LIKE ?", (is_verified, email))
    con.commit()
    con.close()


def get_user_security_questions_enabled(email):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM SecurityQuestions WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return bool(row[1])


def set_user_security_questions_enabled(email, enabled):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("UPDATE SecurityQuestions SET IsEnabled = ? WHERE Email LIKE ?", (enabled, email))
    con.commit()
    con.close()
    return


def get_user_security_questions(email):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM SecurityQuestions WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return row[2:8]


def set_user_security_questions(email, q1, a1, q2, a2, q3, a3):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("UPDATE SecurityQuestions SET IsEnabled = True, Question1 = ?, Answer1 = ?, Question2 = ?, Answer2 = ?, Question3 = ?, Answer3 = ? WHERE Email LIKE ?", (q1, a1, q2, a2, q3, a3, email))
    con.commit()
    con.close()
    return


def check_2fa_enabled(email):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM TwoFA WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return bool(row[1])


def set_2fa_enabled(email, enabled):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("UPDATE TwoFA SET IsEnabled = ? WHERE Email LIKE ?", (enabled, email))
    con.commit()
    con.close()


def insert_evaluation(email, description, contact, photo_path):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("INSERT INTO EvaluationRequests (Email, Description, Contact, PhotoPath) VALUES (?,?,?,?)", (email, description, contact, photo_path))
    con.commit()
    con.close()


def get_all_evaluations():
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM EvaluationRequests")
    rows = cur.fetchall()
    con.commit()
    con.close()
    return rows


def get_user_evaluations(email):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM EvaluationRequests WHERE Email LIKE ?", (email,))
    rows = cur.fetchall()
    con.commit()
    con.close()
    return rows


def get_user_login_attempt_count(email):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("SELECT * FROM LoginCounter WHERE Email LIKE ?", (email,))
    row = cur.fetchone()
    con.commit()
    con.close()
    return row[1]


def set_user_login_attempt_count(email, amount):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()
    cur.execute("UPDATE LoginCounter SET Attempts = ? WHERE Email LIKE ?", (amount, email))
    con.commit()
    con.close()