from flask import Flask, render_template, request, flash, redirect, session, send_file, url_for
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_uploads import configure_uploads, IMAGES, UploadSet
from flask_mail import Mail,Message

from werkzeug.utils import secure_filename
from time import time

from helpers import *
from forms import *

import models
import pyotp
import jwt
import os

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

app.config["RECAPTCHA_PUBLIC_KEY"] = "6LeWLCwpAAAAAIjHqKrw75cjLaTFMQoXaHSHYKQ4"
app.config["RECAPTCHA_PRIVATE_KEY"] = "6LeWLCwpAAAAAItXbSSiS4L2efcIR4ySLEj3kk8r"
app.config['UPLOADED_IMAGES_DEST'] = 'uploads/images'
app.config['MAIL_SERVER'] = "smtp.googlemail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "t.aldentempleman5@gmail.com"
app.config['MAIL_PASSWORD'] = "chuf hbip lulg zuei"

# initialise mail server
mail = Mail(app)

# initialise CSRF protection
csrf = CSRFProtect(app)

# configure path for saving images uploaded through evaluation forms
images = UploadSet('images', IMAGES)
configure_uploads(app, images)


def send_email(title, body, recipients):
    title = title
    sender = "t.aldentempleman5@gmail.com"
    body = body
    msg = Message(title, sender=sender, recipients=recipients, html=body)
    mail.send(msg)


@app.route("/")
def root():
    return render_template("index.html")


@app.route("/evaluations/all")
def all_evaluations():
    if session.get("is_admin"):
        evaluations = models.get_all_evaluations()
        return render_template("allevaluations.html", evaluations=evaluations)

    else:
        flash("You must be an admin to view this page.", "error")
        return redirect("/")


@app.route("/evaluations/request", methods=["GET", "POST"])
def request_evaluation():
    form = RequestEvaluationForm(request.form)

    if request.method == "POST" and form.validate():
        print(form.data)
        email = session["email"]
        description = form.description.data
        contact = form.contact.data
        image = request.files["image"]
        photo_path = None

        if image:
            # TODO: change filename to a secure hash?

            filename = secure_filename(image.filename)
            photo_path = filename
            path = os.path.join(app.config['UPLOADED_IMAGES_DEST'], filename)
            image.save(path)

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
    if not session.get("logged_in"):
        flash("You must log in or register first.", "warning")
        return redirect("/login")

    evaluations = models.get_user_evaluations(session["email"])
    
    return render_template("myevaluations.html", evaluations=evaluations)


@app.route("/evaluations/image/<filename>")
def evaluation_image(filename):
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

        if not models.check_user_exists(email):
            salt = generate_salt()
            hashed_password = hash_password(password, salt)
            twofa_secret = pyotp.random_base32()
            models.insert_user(name, hashed_password, salt, email, phone, twofa_secret)

            # send verification email
            token = jwt.encode({"email": email}, app.secret_key)
            title = "Verify your account"
            sender = "t.aldentempleman5@gmail.com"
            body = render_template("emails/verifypassword.html", token=token)
            msg = Message(title, sender=sender, recipients=[email], html=body)

            try:
                mail.send(msg)
                flash("Verification email sent.", "success")
                return redirect(url_for("login"))
            except Exception as e:
                flash("Error sending verification email.", "error")
                return redirect("/")

        else:
            flash("Email is already registered.", "error")

    if request.method == "GET":
        if session.get("logged_in"):
            flash("You are already logged in.", "warning")
            return redirect("/")

    return render_template("register.html", form=form)


@app.route("/register/verify/<token>")
def verify_email(token):
    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=['HS256'])
        email = data["email"]
    except Exception as e:
        # return HTTP 400 status code for this error
        return "Error decoding verification token.", 400

    if models.check_user_exists(email):
        if models.get_user_verified(email):
            flash(f"Email already verified!", "warning")
            return redirect("/")
        else:    
            models.set_user_verified(email, True)
            models.set_user_login_attempt_count(email, 0)
            flash("Successfully verified email.", "success")
            return redirect("/")
    
    else:
        return f"Email not found!", 404


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)

    if request.method == "POST" and form.validate():
        email = form.email.data.lower()
        password = form.password.data

        if models.check_user_exists(email):
            salt = models.get_user_salt(email)
            given_hashed_password = hash_password(password, salt)

            real_hashed_password = models.get_user_hashed_password(email)
            username = models.get_user_name(email)

            if models.get_user_verified(email):

                if given_hashed_password == real_hashed_password:
                    session["email"] = email
                    session["username"] = username
                    
                    if models.check_2fa_enabled(email):
                        session["awaiting_otp"] = True
                        return redirect("/login/enterotp")

                    elif models.get_user_security_questions_enabled(session["email"]):
                        session["awaiting_questions"] = True
                        return redirect(url_for("enter_security_questions"))

                    else:
                        session["logged_in"] = True
                        models.set_user_login_attempt_count(email, 0)
                        session["is_admin"] = models.check_user_admin(email)
                        flash("You have been successfully logged in.", "success")
                        return redirect("/")

                else:
                    # if more than 10 failed login attempts lock account by
                    # 'unverifying it' and requiring a new verification email
                    # to reactivate account.
                    attempts = models.get_user_login_attempt_count(email)
                    models.set_user_login_attempt_count(email, attempts + 1)
                    if attempts > 5:
                        models.set_user_verified(email, False)
                        # send verification email
                        token = jwt.encode({"email": email}, app.secret_key)
                        title = "Reverify your account"
                        body = render_template("emails/verifypassword.html", token=token)
                        
                        send_email(title, body, email)
                        flash("5 failed login attempts. Account locked. Reverify your account via email to regain access", "error")
                        return redirect(url_for("login"))

                    flash("Incorrect password.", "error")
                    return redirect("/login")

            else:
                flash("Account email must be verified before logging in.", "warning")
                return redirect("/login")
            
        else:
            flash("No account exists with that email.", "error")
            return redirect("/login")

    if request.method == "GET":
        if session.get("logged_in"):
            flash("You are already logged in.", "warning")
            return redirect("/")

        if session.get("awaiting_otp"):
            del session["awaiting_otp"]
            return redirect("/login")

    return render_template("login.html", form=form)


@app.route("/login/enterotp", methods=["GET", "POST"])
def enterotp():
    form = EnterOTP(request.form)

    if request.method == "POST" and form.validate():
        # ensure submitted OTP is numeric
        try:
            otp = int(form.otp.data)
        except ValueError:
            flash("Invalid OTP.", "error")
            return redirect("/login/enterotp")

        # use user's secret to construct TOTP authenticator    
        secret = models.get_user_2fa_secret(session["email"])
        encoded_secret = bytearray(secret, 'ascii').decode('utf-8')
        totp = pyotp.TOTP(encoded_secret)
        # verify the submitted OTP against what it should be
        correct_otp = totp.verify(otp)

        # if correct OTP, continue
        if correct_otp:
            # redirect to security questions if they are enabled
            if models.get_user_security_questions_enabled(session["email"]):
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
            flash("Incorrect OTP.", "error")
            return redirect(url_for("enterotp"))

    elif request.method == "GET":
        # redirect away if already logged in
        if session.get("logged_in"):
            flash("You are already logged in.", "warning")
            return redirect("/")

        # redirect away if they should not be at this login stage
        if not session.get("awaiting_otp"):
            return redirect("/")
        
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
            flash("Incorrect security questions.", "error")
            return redirect(url_for("enter_security_questions"))

    elif request.method == "GET":
        # put each question as the label for each input box
        form.answer1.label = q1
        form.answer2.label = q2
        form.answer3.label = q3

        return render_template("entersecurityquestions.html", form=form)


@app.route("/logout", methods=["POST"])
def logout():
    if session.get("logged_in"):
        session.clear()
        flash("You have been successfully logged out.", "success")
    
    return redirect("/")


@app.route("/account")
def account():
    if not session.get("logged_in"):
        flash("You must log in or register first.", "warning")
        return redirect("/login")

    return render_template("account.html")


@app.route("/account/delete", methods=["POST", "GET"])
def delete_account():
    form = DeleteAccountForm(request.form)

    if not session.get("logged_in"):
        flash("You must log in or register first.", "warning")
        return redirect("/login")

    if request.method == "POST":
        models.delete_user(session.get("email"))
        session.clear()
        flash("Account successfully deleted.", "success")
        return redirect("/")

    if request.method == "GET":
        return render_template("deleteaccount.html", form=form)


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

            # generate the reset password email
            title = "Reset your password"
            body = render_template("emails/resetpassword.html", token=token)
            # send the reset password email
            send_email(title, body, email)
            flash("Request sent. Use link your email inbox.", "success")
            return redirect("/")

            try:
                mail.send(msg)
                flash("Request sent. Use link your email inbox.", "success")
                return redirect("/")
            except Exception as e:
                flash("Error sending verification email.", "error")
                return redirect(url_for("request_password_reset"))

        else:
            flash("Email does not exist.", "error")
            return redirect(url_for("request_password_reset"))

    if request.method == "GET":
        return render_template("requestresetpassword.html", form=form)


@app.route("/account/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    form = ResetPasswordForm(request.form)

    # try to decode data (i.e., email) from the reset password token
    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=['HS256'])
        email = data["email"]
        expires = data["expires"]

    except Exception as e:
        # return HTTP 400 status code if it token can not be decoded
        return "Error decoding token.", 400

    # make sure reset password link has not expired
    if time() > expires:
        flash("Reset password link has expired. Request a new one.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_password = form.password.data
        salt = models.get_user_salt(email)
        # hash new password
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


@app.route("/account/managesecurityquestions", methods=["GET", "POST"])
def manage_security_questions():
    form = ManageSecurityQuestions(request.form)
    email = session.get("email")

    if request.method == "POST":
        if email:
            # update questions and answers in database with the new ones
            # from the form
            q1, q2, q3 = form.question1.data, form.question2.data, form.question3.data
            a1, a2, a3 = form.answer1.data, form.answer2.data, form.answer3.data
            models.set_user_security_questions(email, q1, a1, q2, a2, q3, a3)
            
            flash("Successfully updated security questions.", "success")
            return redirect(url_for("manage_security_questions"))

    elif request.method == "GET":
        if not session.get("logged_in"):
            flash("You must log in or register first.", "warning")
            return redirect(url_for("login"))

        if email:
            # autofill form with previous questions and answers
            old_questions = models.get_user_security_questions(email)
            form.question1.data = old_questions[0]
            form.answer1.data = old_questions[1]
            form.question2.data = old_questions[2]
            form.answer2.data = old_questions[3]
            form.question3.data = old_questions[4]
            form.answer3.data = old_questions[5]
        
        return render_template("managesecurityquestions.html", form=form)


@app.route("/account/manage2fa", methods=["GET", "POST"])
def manage2fa():
    form = Manage2FA(request.form)

    if request.method == "POST":
        email = session.get("email")
        if email:
            # if the user presses the "Enable 2FA" button
            if form.enable.data:
                models.set_2fa_enabled(email, True)
                flash("Successfully enabled 2FA.", "success")
                return redirect(url_for("manage2fa"))

            # elif the user presses the "Disable 2FA" button
            elif form.disable.data:
                models.set_2fa_enabled(email, False)
                flash("Successfully disabled 2FA.", "success")
                return redirect(url_for("manage2fa"))

        else:
            return "Invalid email.", 400        

    elif request.method == "GET":
        if not session.get("logged_in"):
            flash("You must log in or register first.", "warning")
            return redirect("/login")

        enabled = models.check_2fa_enabled(session.get("email")) # is 2fa enabled?
        secret = models.get_user_2fa_secret(session.get("email")) # 2fa secret
        
        return render_template("manage2fa.html", enabled=enabled, secret=secret, form=form)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return f"{e}", 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
