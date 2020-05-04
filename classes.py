import hashlib
from hashlib import sha256
from random import choice
import string
from werkzeug.utils import secure_filename
import os
import smtplib, ssl
from datetime import datetime, timedelta
from app.login import current_user
from app.models import User

class UploadedImage():

    def __init__(self, imageName):
        self.imageName = str(imageName)

    def imageCheck(self):
        supported_p_types = ['.png', '.jpeg', '.jpg']
        check_picture_type = any(pic in str(self.imageName) for pic in supported_p_types)

        return check_picture_type

    @staticmethod
    def imageID(StringLength=16):
        ''' Generated imageID which will be used to rename image + add to DB column '''
        generated_img_id = string.ascii_letters + string.digits
        return''.join(choice(generated_img_id) for i in range(StringLength))

    @staticmethod
    def imageSave(location, filename, directory):
        if '.png' in str(location):
            extension = '.png'
        elif 'jpg' in str(location):
            extension = 'jpg'
        elif 'jpeg' in str(location):
            extension = 'jpeg'

        imageID = UploadedImage.imageID()
        save_to_uploads_filename = secure_filename(location)
        save_to_uploads_data = filename
        save_to_uploads_data.save(f'{imageID}.{extension}')

        os.replace(f'{imageID}.{extension}', f'app/static/uploads/{directory}/{imageID}.{extension}')

        return f'{imageID}.{extension}'

class Emails():
    '''All methods involving emails. This includes new user registration, email verification upon login, reset password'''

    def __init__(self, email):
        self.email = email

    @staticmethod
    def emailInformation(to, message):
        try:
            server_ssl = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            gmail_user = 'email@gmail.com'
            gmail_pass = 'password123'
            server_ssl.login(gmail_user, gmail_pass)
            server_ssl.sendmail(gmail_user, to, message)
            server_ssl.close()
        except Exception as e:
          print(e)


    def newUserVerification(self, verify_link):
        to = self.email
        subject = 'Verify Your Account'
        body = f'Please verify your new account by visiting this link: site.com/account/verification/verifyID/{verify_link}'
        message = f'Subject: {subject}\n\n{body}'

        self.emailInformation(to, message)

    def newUserEmail(self):
        to = self.email
        subject = 'Welcome to Site'
        body = 'Welcome to the website. You can now login'
        message = f'subject: {subject}\n\n{body}'
        
        emailInformation(to, message)


    def sendVerificationEmail(self, ip, verification_code):
        to = self.email
        subject = 'Verify Login'
        body = f'Please Verify login from IP:{ip}. Here is your unique code: {verification_code}. If you did not request to login, please reset your password'
        message = f'Subject: {subject}\n\n{body}'
        
        self.emailInformation(to, message)


    def resetPassword(self, resetID):
        to = self.email
        subject = 'Reset Password'
        body = f'You have requested to reset your password. Please visit the following link to complete your password reset. Site.com/auth/password/reset/{resetID}'
        message = f'Subject: {subject}\n\n{body}'

        self.emailInformation(to, message)

    def newPassword(self):
        to = self.email
        subject = 'Your password has been reset'
        body = 'Your password has been reset. If you did not authorise this, please contact support'
        message = f'Subject: {subject}\n\n{body}'

        self.emailInformation(to, message)

    def accountLocked(self):
        to = self.email
        subject = 'Account Locked'
        body = 'Your account has been locked due to many login attemps'
        message = f'Subject: {subject}\n\n{body}'
        
        self.emailInformation(to, message)

    def unauthorised_access(self, ip):
        to = self.email
        subject = 'Unauthorised Access'
        body = f'Someone attempted to create a new admin account from IP address: {ip}'
        message = f'Subject: {subject}\n\n{body}'

        self.emailInformation(to, message) 
    
class EmailVerification():
    def __init__(self, email):
        self.email = email

    @staticmethod
    def emailVerificationCode(StringLength=8):
        ''' Generated verification code '''
        generated_code = string.ascii_letters + string.digits
        return ''.join(choice(generated_code) for i in range(StringLength))

    @staticmethod
    def verifyAccountLink(StringLength=58):
        ''' Generated link to activate account '''
        accountLink = string.digits + string.ascii_letters
        return ''.join(choice(accountLink) for i in range(StringLength))

    def check_email_code(self, emailCode):
        ''' Check if verification code is valid '''
        code_check = User.query.filter_by(email=self.email).first()
        if code_check.email_verification == emailCode:
            return True
        else:
            return False

    def delete_email_verification_code(self):
        ''' Delete email verification code from DB '''
        fetch_code = User.query.filter_by(email=self.email).first()
        fetch_code.email_verification = None
        fetch_code.update()
        return True
