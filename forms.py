from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField, BooleanField, TextField, validators, IntegerField, FileField
from wtforms.validators import InputRequired, Email, Length, NumberRange

## Admin Page Forms 

class AdminRegister(FlaskForm):
    email = StringField(validators=[InputRequired(), Email('Invalid Email'), Length(max=300)])
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=100)])
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=8, max=100)])
    profile_img = FileField(validators=[InputRequired()])
    submit = SubmitField('Register')

class AdminLogin(FlaskForm):
    email = StringField(validators=[InputRequired(), Email('Invalid Email'), Length(max=300)])
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=100)])
    submit = SubmitField('Login')

class LoginVerify(FlaskForm):
    email_code = StringField(validators=[InputRequired()])
    submit = SubmitField('Submit')

## User Regiester Forms

class UserRegister(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField(validators=[Email(message='Invalid Email'), InputRequired(), Length(min=10, max=300)])
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=50)])
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=6, max=50)])
    profile_img = FileField(validators=[InputRequired()])
    role = RadioField('Account Type', choices=[('SELLER', 'Become a seller'), ('BUYER', 'Become a buyer')], validators=[InputRequired()])
    submit = SubmitField('Register')

class UserLoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=6, max=300)])
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=100)])
    submit = SubmitField('Login')

class ResetPassword(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Length(min=5), Email(message='Invalid Email')])
    submit = SubmitField('Reset Password')

class SetPassword(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired(), Length(min=10)])
    submit = SubmitField('Submit')