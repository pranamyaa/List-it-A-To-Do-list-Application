from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField,FileField
from wtforms.validators import DataRequired, Length
from wtforms.widgets import PasswordInput

class LoginForm(FlaskForm):
    Username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    Password = StringField('Password', widget=PasswordInput(hide_value=False), validators=[DataRequired()])
    submit = SubmitField('Log in')

class RegistrationForm(FlaskForm):
    Email_ID = StringField('Email_ID', validators=[DataRequired()])
    Username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    Password = StringField('Password', widget=PasswordInput(hide_value=False), validators=[DataRequired()])
    First_name = StringField('First_name', validators=[DataRequired()])
    Last_name = StringField('Last_name', validators=[DataRequired()])
    Profile_img = FileField('Profile_img', validators=[DataRequired()])
    Phone_no = StringField('Phone_no', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class VerificationForm(FlaskForm):
    Verification_code = StringField('Verification_code', validators=[DataRequired()])
    submit = SubmitField('verify')