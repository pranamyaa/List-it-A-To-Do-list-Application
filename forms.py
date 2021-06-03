from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField,FileField
from wtforms.validators import DataRequired, Length
from wtforms.widgets import PasswordInput

class LoginForm(FlaskForm):
    user_name = StringField('user_name', validators=[DataRequired(), Length(min=2, max=20)])
    Password = StringField('Password', widget=PasswordInput(hide_value=False), validators=[DataRequired()])
    submit = SubmitField('Log in')

class RegistrationForm(FlaskForm):
    Email_ID = StringField('Email_ID', validators=[DataRequired()])
    user_name = StringField('user_name', validators=[DataRequired(), Length(min=2, max=20)])
    Password = StringField('Password', widget=PasswordInput(hide_value=False), validators=[DataRequired()])
    given_name = StringField('given_name', validators=[DataRequired()])
    family_name = StringField('family_name', validators=[DataRequired()])
    profile_img = FileField('profile_img', validators=[DataRequired()])
    phone_no = StringField('phone_no', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class VerificationForm(FlaskForm):
    verification_code = StringField('verification_code', validators=[DataRequired()])
    submit = SubmitField('verify')