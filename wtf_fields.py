from flask_wtf import FlaskForm
from main import db
from wtforms import StringField, PasswordField, SubmitField, EmailField
from passlib.hash import pbkdf2_sha256
from wtforms.validators import InputRequired, Length, EqualTo, ValidationError


def invalid_credentials(form, field):
    username_entered = form.username.data
    password_entered = field.data
    user = db.users.find_one({"username": username_entered})
    if user is None:
        raise ValidationError("Username or Password is Incorrect")
    elif not pbkdf2_sha256.verify(password_entered, user["password"]):
        raise ValidationError("Username or Password is Incorrect")


class RegistrationForm(FlaskForm):
    username = StringField(
        "username-label",
        validators=[
            InputRequired(message="Username Required"),
            Length(
                min=4, max=20, message="Username must be between 4 and 20 characters "
            ),
        ],
    )
    email = EmailField(
        "email-label", validators=[InputRequired(message="Email Required")]
    )
    password = PasswordField(
        "password-label",
        validators=[
            InputRequired(message="Password Required"),
            Length(
                min=4, max=20, message="Password must be between 4 and 20 characters "
            ),
        ],
    )
    confirm_pswd = PasswordField(
        "confirm_pswd-label",
        validators=[
            InputRequired(message="Username Required"),
            EqualTo("password", message="Confirm Password must match to password"),
        ],
    )
    submin_btn = SubmitField("Create")

    def validate_username(self, username):
        user_obj = db.users.find_one({"username": username.data})
        group_obj = db.groups.find_one({"name": username.data})
        if user_obj:
            raise ValidationError("Username already exists!!")
        if group_obj:
            raise ValidationError("Username should not match with groupname")


class LoginForm(FlaskForm):
    username = StringField(
        "username_label", validators=[InputRequired(message="Username Required")]
    )
    password = PasswordField(
        "password_label",
        validators=[InputRequired(message="Password Required"), invalid_credentials],
    )
    submin_btn = SubmitField("Login")
