from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from wtforms import StringField, PasswordField, SubmitField, ValidationError, StringField
from models import Users


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')
    error = StringField('error', default="")


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo(
        'password2', message='Passwords must match')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if Users.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if Users.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')


class PasswordResetForm(FlaskForm):    
    new_password = PasswordField('New Password', validators=[
                                 DataRequired(), EqualTo('new_password2', message='Passwords must match')])
    new_password2 = PasswordField(
        'Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')
