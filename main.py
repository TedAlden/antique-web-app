from flask import Flask, render_template, request, flash, redirect, session, send_file, url_for
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_uploads import configure_uploads, IMAGES, UploadSet
from flask_mail import Mail, Message

from werkzeug.utils import secure_filename
from dotenv import dotenv_values
from time import time

from helpers import *
from forms import *

import models
import pyotp
import jwt
import os


app = Flask(__name__)
app.config.from_mapping(dotenv_values())
app.testing = True

# initialise mail server
mail = Mail(app)

# initialise CSRF protection
csrf = CSRFProtect(app)

# configure path for saving images uploaded through evaluation forms
images = UploadSet('images', IMAGES)
configure_uploads(app, images)


def send_email(title: str, body: str, recipient: str):
    title = title
    sender = app.config['MAIL_USERNAME']
    body = body
    msg = Message(title, sender=sender, recipients=[recipient], html=body)
    mail.send(msg)


@app.route("/")
def root():
    return render_template("index.html")


@app.route("/evaluations/all")
def all_evaluations():
    # check that user is an admin in order to view this page
    if session.get("is_admin"):
        evaluations = models.get_all_evaluations()
        return render_template("allevaluations.html", evaluations=evaluations)

    else:
        flash("You must be an admin to view this page.", "danger")
        return redirect("/")


@app.route("/evaluations/request", methods=["GET", "POST"])
def request_evaluation():
    form = RequestEvaluationForm(request.form)

    if request.method == "POST" and form.validate():
        email = session.get("email")
        description = form.description.data
        contact = form.contact.data
        image = request.files["image"]
        photo_path = None

        # if the evaluation form had an image in it, save it to the
        # server and store its path in the database
        if image:
            # TODO: change filename to a secure hash?

            filename = secure_filename(image.filename)
            photo_path = filename
            path = os.path.join(app.config['UPLOADED_IMAGES_DEST'], filename)
            image.save(path)

        # save evaluation request into database
        models.insert_evaluation(email, description, contact, photo_path)

        flash("Successfully sent evaluation request!", "success")
        return redirect(url_for("request_evaluation"))
    
    if request.method == "GET":
        # if user is not logged in, redirect them to log in page
        if not session.get("logged_in"):
            flash("You must log in or register first.", "warning")
            return redirect(url_for("login"))

        # otherwise show the "request evaluation" page
        return render_template("requestevaluation.html", form=form)


@app.route("/evaluations/my")
def my_evaluations():
    # redirect the user to the login page if they are not logged in, as
    # only logged-in users should see this
    if not session.get("logged_in"):
        flash("You must log in or register first.", "warning")
        return redirect("/login")

    evaluations = models.get_user_evaluations(session.get("email"))
    
    return render_template("myevaluations.html", evaluations=evaluations)


@app.route("/evaluations/image/<filename>")
def evaluation_image(filename):
    # this route makes the saved evaluation images accessible publicly
    path = os.path.join(app.config['UPLOADED_IMAGES_DEST'], filename)

    # TODO: add authentication here

    return send_file(path, mimetype='image/gif')


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)

    if request.method == "POST" and form.validate():
        email = form.email.data
        password = form.password.data
        name = form.name.data
        phone = form.phone.data

        # check if email is not already registered with an account
        if not models.check_user_exists(email):
            # hash and salt password, and generate 2FA secret
            salt = generate_salt()
            hashed_password = hash_password(password, salt)
            twofa_secret = pyotp.random_base32()
            # insert user into database
            models.insert_user(name, hashed_password, salt, email, phone, twofa_secret)

            # send verification email
            title = "Verify your account"
            token = jwt.encode({"email": email}, app.secret_key)
            body = render_template("emails/verifypassword.html", token=token)
            send_email(title, body, email)

            flash("Verification email sent.", "success")
            return redirect(url_for("login"))

        else:
            flash("Email is already registered.", "danger")

    if request.method == "GET":
        # check if user is not already logged in
        if session.get("logged_in"):
            flash("You are already logged in.", "warning")
            return redirect("/")

    return render_template("register.html", form=form)


@app.route("/register/verify/<token>")
def verify_email(token):
    # attempt to decode the token in the verification link URL
    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=['HS256'])
        email = data["email"]
    except Exception as e:
        # return HTTP 400 status code for this error
        return "Error decoding verification token.", 400

    # check if the decoded email exists
    if models.check_user_exists(email):
        # check if email is not already verified
        if not models.get_user_verified(email):
            # verify the email
            models.set_user_verified(email, True)
            models.set_user_login_attempt_count(email, 0)

            flash("Successfully verified email.", "success")
            return redirect("/")
        else:   
            flash(f"Email already verified!", "warning")
            return redirect("/")

    else:
        return f"Email not found!", 404


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)

    if request.method == "POST" and form.validate():
        email = form.email.data.lower()
        password = form.password.data

        # first, check if the email exists as an account
        if models.check_user_exists(email):
            # hash the password submitted using the user's salt
            salt = models.get_user_salt(email)
            given_hashed_password = hash_password(password, salt)

            real_hashed_password = models.get_user_hashed_password(email)
            username = models.get_user_name(email)

            # check if the account with this email is verified
            if models.get_user_verified(email):
                
                # compare the hash of the submitted password to the hash
                # stored in the database
                if given_hashed_password == real_hashed_password:
                    session["email"] = email
                    session["username"] = username
                    
                    # if the account has 2fa enabled, redirect them
                    # there before completing the login
                    if models.check_2fa_enabled(email):
                        session["awaiting_otp"] = True
                        return redirect("/login/enterotp")

                    # if the account has security questions configured,
                    # redirect them there before completing the login
                    elif models.get_user_security_questions_enabled(session["email"]):
                        session["awaiting_questions"] = True
                        return redirect(url_for("enter_security_questions"))

                    # otherwise, complete the login process now
                    else:
                        session["logged_in"] = True
                        session["is_admin"] = models.check_user_admin(email)
                        models.set_user_login_attempt_count(email, 0)

                        flash("You have been successfully logged in.", "success")
                        return redirect("/")

                else:
                    # if more than 5 failed login attempts lock account by
                    # 'unverifying it' and requiring a new verification email
                    # to reactivate account.
                    attempts = models.get_user_login_attempt_count(email)
                    attempts += 1
                    models.set_user_login_attempt_count(email, attempts)
                    if attempts > 5:
                        models.set_user_verified(email, False)
                        # send re-verification email
                        token = jwt.encode({"email": email}, app.secret_key)
                        title = "Reverify your account"
                        body = render_template("emails/verifypassword.html", token=token)
                        send_email(title, body, email)

                        flash("Exceeded 5 failed login attempts. Please reverify your account via email to regain access.", "danger")
                        return redirect(url_for("login"))

                    flash("Incorrect password.", "danger")
                    return redirect(url_for("login"))

            else:
                flash("Account email must be verified before logging in.", "warning")
                return redirect("/login")
            
        else:
            flash("No account exists with that email.", "danger")
            return redirect("/login")

    if request.method == "GET":
        # if the user is already logged in, redirect them away
        if session.get("logged_in"):
            flash("You are already logged in.", "warning")
            return redirect("/")

        # if the user was already part-way through the login process,
        # i.e, awaiting their entry of a 2FA pin or security questions,
        # then cancel that login attempt and reset, ready to restart the
        # login process again.
        if session.get("awaiting_otp"):
            del session["awaiting_otp"]
            return redirect("/login")

        if session.get("awaiting_questions"):
            del session["awaiting_questions"]
            return redirect("/login")

    return render_template("login.html", form=form)


@app.route("/login/enterotp", methods=["GET", "POST"])
def enterotp():
    form = EnterOTP(request.form)

    # redirect away if they should not be at this login stage
    if not session.get("awaiting_otp"):
        return redirect("/")

    # redirect away if already logged in
    if session.get("logged_in"):
        flash("You are already logged in.", "warning")
        return redirect("/")

    if request.method == "POST" and form.validate():
        email = session.get("email")
        # ensure submitted OTP is numeric
        try:
            otp = int(form.otp.data)
        except ValueError:
            flash("Invalid OTP.", "danger")
            return redirect("/login/enterotp")

        # use the user's secret to construct a TOTP authenticator    
        secret = models.get_user_2fa_secret(session["email"])
        encoded_secret = bytearray(secret, 'ascii').decode('utf-8')
        totp = pyotp.TOTP(encoded_secret)
        # verify the submitted OTP against what it should be
        correct_otp = totp.verify(otp)

        # if the OTP is correct...
        if correct_otp:
            # redirect to security questions if they are enabled
            if models.get_user_security_questions_enabled(email):
                session["awaiting_questions"] = True
                del session["awaiting_otp"]

                return redirect(url_for("enter_security_questions"))

            # otherwise, login
            else:
                session["logged_in"] = True
                session["is_admin"] = models.check_user_admin(email)
                models.set_user_login_attempt_count(email, 0)
                del session["awaiting_otp"]

                flash("You are now logged in.", "success")
                return redirect("/")

        # if incorrect OTP, allow another attempt
        else:
            flash("Incorrect OTP.", "danger")
            return redirect(url_for("enterotp"))

    if request.method == "GET":
        return render_template("enterotp.html", form=form)


@app.route("/login/entersecurityquestions", methods=["GET", "POST"])
def enter_security_questions():
    form = EnterSecurityQuestions(request.form)

    # redirect away if the user should not be at this login stage
    if not session.get("awaiting_questions"):
        return redirect("/")

    # redirect away if already logged in
    if session.get("logged_in"):
        flash("You are already logged in.", "warning")
        return redirect("/")

    # attempt to get the email of the user in the current session
    email = session.get("email")
    if not email:
        return 400

    # get security questions and answers for the user
    questions_answers = models.get_user_security_questions(email)
    q1, q2, q3 = questions_answers[0::2]
    a1, a2, a3 = questions_answers[1::2]

    if request.method == "POST" and form.validate():
        # verify the answer to each security question is correct
        if form.answer1.data == a1 and form.answer2.data == a2 and form.answer3.data == a3:
            # log user in
            session["logged_in"] = True
            session["is_admin"] = models.check_user_admin(email)
            models.set_user_login_attempt_count(email, 0)
            del session["awaiting_questions"]
            flash("You have been successfully logged in.", "success")
            return redirect("/")
        # keep them on this page if the answers are wrong
        else:
            flash("Incorrect security questions.", "danger")
            return redirect(url_for("enter_security_questions"))

    if request.method == "GET":
        # put each question as the label for each input box
        form.answer1.label = q1
        form.answer2.label = q2
        form.answer3.label = q3

        return render_template("entersecurityquestions.html", form=form)


@app.route("/logout", methods=["POST"])
def logout():
    # user can only logout if they are already logged in
    if session.get("logged_in"):
        session.clear()
        flash("You have been successfully logged out.", "success")
    
    return redirect("/")


@app.route("/account")
def account():
    # Require user to be logged in to view the account settings page
    if not session.get("logged_in"):
        flash("You must log in or register first.", "warning")
        return redirect("/login")
    
    # Get info from database model
    email = session.get("email")
    questions = models.get_user_security_questions(email)
    questions_enabled = models.get_user_security_questions_enabled(email)
    twofa_enabled = models.check_2fa_enabled(email)
    twofa_secret = models.get_user_2fa_secret(email)

    # Create WTForm objects
    questions_form = ManageSecurityQuestions()
    twofa_form = Manage2FA()
    delete_form = DeleteAccountForm()

    # Pre-populate forms with existing information
    questions_form.question1.data = questions[0]
    questions_form.answer1.data = questions[1]
    questions_form.question2.data = questions[2]
    questions_form.answer2.data = questions[3]
    questions_form.question3.data = questions[4]
    questions_form.answer3.data = questions[5]
    questions_form.enabled.data = questions_enabled
    twofa_form.enabled.data = twofa_enabled

    return render_template("account.html", questions_form=questions_form, twofa_form=twofa_form, twofa_secret=twofa_secret, delete_form=delete_form)


@app.route("/account/delete", methods=["POST"])
def delete_account():
    form = DeleteAccountForm(request.form)

    # user can only delete their account if logged in
    if not session.get("logged_in"):
        flash("You must log in or register first.", "warning")
        return redirect("/login")

    if request.method == "POST":
        # delete user and clear session
        models.delete_user(session.get("email"))
        session.clear()

        flash("Account successfully deleted.", "success")
        return redirect("/")


@app.route("/account/reset-password", methods=["GET", "POST"])
def request_password_reset():
    form = RequestResetPasswordForm(request.form)

    if request.method == "POST" and form.validate():
        email = form.email.data

        # check if email is registered to an account
        if models.check_user_exists(email):
            # generate token for reset password email
            token = jwt.encode({'email': email,
                                'expires': time() + 600},
                                key=app.config["SECRET_KEY"])
            
            # send the reset password email
            title = "Reset your password"
            body = render_template("emails/resetpassword.html", token=token)
            send_email(title, body, email)

            flash("Request sent. Use link your email inbox.", "success")
            return redirect("/")

        else:
            flash("Email does not exist.", "danger")
            return redirect(url_for("request_password_reset"))

    if request.method == "GET":
        return render_template("requestresetpassword.html", form=form)


@app.route("/account/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    form = ResetPasswordForm(request.form)

    # try to decode data from the reset password token
    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=['HS256'])
        email = data["email"]
        expires = data["expires"]

    except Exception as e:
        # return HTTP 400 status code if it token can not be decoded
        return "Error decoding token.", 400

    # make sure the reset password link has not expired
    if time() > expires:
        flash("Reset password link has expired. Request a new one.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        # hash new password
        new_password = form.password.data
        salt = models.get_user_salt(email)
        new_password_hashed = hash_password(new_password, salt)
        # update database with new password hash
        models.set_user_hashed_password(email, new_password_hashed)

        flash("Successfully reset password.", "success")
        return redirect(url_for("login"))

    if request.method == "GET":
        # check user exists first
        if models.check_user_exists(email):
            return render_template("resetpassword.html", form=form, token=token)

        else:
            return f"Email not found!", 404


@app.route("/account/managesecurityquestions", methods=["POST"])
def manage_security_questions():
    form = ManageSecurityQuestions(request.form)
    email = session.get("email")

    if request.method == "POST":
        if email:
            # update questions and answers in database with the new ones
            # from the form
            q1, q2, q3 = form.question1.data, form.question2.data, form.question3.data
            a1, a2, a3 = form.answer1.data, form.answer2.data, form.answer3.data
            enabled = form.enabled.data

            models.set_user_security_questions(email, q1, a1, q2, a2, q3, a3)
            models.set_user_security_questions_enabled(email, enabled)
            
            flash("Successfully updated security questions.", "success")
            # return redirect(url_for("manage_security_questions"))
            return redirect(url_for("account"))


@app.route("/account/manage2fa", methods=["POST"])
def manage2fa():
    form = Manage2FA(request.form)

    if request.method == "POST":
        email = session.get("email")
        if email:
            if form.enabled.data:
                models.set_2fa_enabled(email, True)
                flash("Successfully enabled 2FA.", "success")
                return redirect(url_for("account"))
            else:
                models.set_2fa_enabled(email, False)
                flash("Successfully disabled 2FA.", "success")
                return redirect(url_for("account"))

        else:
            return "Invalid email.", 400


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return f"{e}", 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
