from flask_wtf.recaptcha import RecaptchaField
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import Form, BooleanField, StringField, PasswordField, \
        validators, ValidationError, SubmitField, SelectField, TextAreaField

import re


SECURITY_QUESTIONS = [
    "In what city were you born?",
    "What is the name of your favorite pet?",
    "What is your mother's maiden name?",
    "What high school did you attend?",
    "What was the name of your elementary school?",
    "What was the make of your first car?",
    "What was your favorite food as a child?",
    "Where did you meet your spouse?"
]


class LoginForm(Form):
    email = StringField('Email Address', [
        validators.DataRequired()
    ])
    password = PasswordField('Password', [
        validators.DataRequired()
    ])
    recaptcha = RecaptchaField('ReCaptcha')


class RegisterForm(Form):
    email = StringField('Email Address', [
        validators.DataRequired(),
        validators.Email()
    ])
    password = PasswordField('Password', [
        validators.DataRequired()
    ])
    name = StringField('Name', [
        validators.DataRequired(),
        validators.length(2, 30)
    ])
    phone = StringField('Phone', [
        validators.DataRequired()
    ])

    def validate_password(form, field):
        password = field.data
        
        # check password for certain requirements
        if len(password) < 8:
            raise ValidationError('Password must be 8 characters or more.')

        if re.search(r"\d", password) is None:
            raise ValidationError('Password must contain digits.')

        if re.search(r"[A-Z]", password) is None:
            raise ValidationError('Password must contain uppercase characters.')

        if re.search(r"[a-z]", password) is None:
            raise ValidationError('Password must contain lowercase characters.')

        if re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None:
            raise ValidationError('Password must contain symbols.')


class RequestEvaluationForm(Form):
    description = TextAreaField('Request Details', [
        validators.DataRequired(),
        validators.length(20, 5000)
    ])
    contact = SelectField('Contact Method', [
        validators.DataRequired()],
        choices=[('Phone', 'Phone'), ('Email', 'Email')]
    )
    image = FileField('Image', validators=[
        FileAllowed(['jpg', 'png'], 'Images only!')
    ])


class RequestResetPasswordForm(Form):
    email = StringField('Email Address', [
        validators.DataRequired()
    ])


class ResetPasswordForm(Form):
    password = PasswordField('Password', [
        validators.DataRequired()
    ])

    def validate_password(form, field):
        password = field.data
        
        # check password for certain requirements
        if len(password) < 8:
            raise ValidationError('Password must be 8 characters or more.')

        if re.search(r"\d", password) is None:
            raise ValidationError('Password must contain digits.')

        if re.search(r"[A-Z]", password) is None:
            raise ValidationError('Password must contain uppercase characters.')

        if re.search(r"[a-z]", password) is None:
            raise ValidationError('Password must contain lowercase characters.')

        if re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None:
            raise ValidationError('Password must contain symbols.')


class Manage2FA(Form):
    enable = SubmitField()
    disable = SubmitField()


class DeleteAccountForm(Form):
    delete = SubmitField()


class EnterOTP(Form):
    otp = StringField('OTP', [
        validators.DataRequired()
    ])


class ManageSecurityQuestions(Form):
    question1 = SelectField('Question 1', [
        validators.DataRequired()],
        choices=[*zip(SECURITY_QUESTIONS, SECURITY_QUESTIONS)]
    )
    answer1 = StringField('Answer 1', [
        validators.DataRequired()
    ])
    question2 = SelectField('Question 2', [
        validators.DataRequired()],
        choices=[*zip(SECURITY_QUESTIONS, SECURITY_QUESTIONS)]
    )
    answer2 = StringField('Answer 2', [
        validators.DataRequired()
    ])
    question3 = SelectField('Question 3', [
        validators.DataRequired()],
        choices=[*zip(SECURITY_QUESTIONS, SECURITY_QUESTIONS)]
    )
    answer3 = StringField('Answer 3', [
        validators.DataRequired()
    ])


class EnterSecurityQuestions(Form):
    answer1 = StringField('INSERT QUESTION 1', [
        validators.DataRequired()
    ])
    answer2 = StringField('INSERT QUESTION 2', [
        validators.DataRequired()
    ])
    answer3 = StringField('INSERT QUESTION 3', [
        validators.DataRequired()
    ])
