from app.database import db
import ipapi
from flask import request, render_template
from datetime import datetime, timedelta
from random import choice
import string
import hashlib
from hashlib import sha256

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255))
    email = db.Column(db.String(255))
    password = db.Column(db.String(255))
    reg_ip = db.Column(db.String(255)) 
    c_date = db.Column(db.String(255))
    p_img = db.Column(db.String(255))
    role = db.Column(db.String(300))
    email_verification = db.Column(db.String(50), nullable=True)
    lock_status = db.Column(db.Boolean, default=False)
    locked_until = db.Column(db.String(100))
    verification_fails = db.Column(db.Integer, default=0)
    activation_link = db.Column(db.String(300), nullable=True)
    account_status = db.Column(db.Boolean, default=False)
    password_reset_code = db.Column(db.String(300), nullable=True)
    TrustedSession = db.relationship('TrustedSession')

    def add(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete()
        db.session.commit()
    
    def get_id(self):
        return self.id
    def is_authenticated(self):
        return True
    def get_username(self):
        return self.username
    def is_active(self):
        return True
    def get_role(self):
        return self.role
    def is_anonymous(self):
        return False

    ## Admin Methods

    @staticmethod
    def check_for_admin():
        ''' Checks is an Admin exists in the DB. returns False if Admin is not setup'''
        admin_check = User.query.filter_by(role='ADMIN').first()
        if admin_check is None:
            return False
        return True
    
    @staticmethod
    def check_if_admin(email):
        query = User.query.filter_by(email=email).first()

        if query is None:
            return False
        if query.role != 'ADMIN':
            return False

        return True

    @staticmethod
    def check_admin_ip(ip):
        ''' Check if current IP matches reg IP // checks if its been added to the trusted db '''

        admin_check = User.query.filter_by(role='ADMIN').first()
        if admin_check.reg_ip != ip:
            check_trusted_ips = TrustedSession.query.filter_by(userID=admin_check.id).first()

            if check_trusted_ips is None:
                return False
            if check_trusted_ips.ip is None:
                return False

        return True


    @staticmethod
    def userIP():
        ''' Get user IP '''
        user_ip = ipapi.location(None, None, 'ip')
        return user_ip

    @staticmethod
    def check_form_email_validation(email):
        ''' Check email submitted is valid email '''
        if '@' not in email:
            message = 'Invalid Email'
            return False
        return True

    @staticmethod
    def check_email(email):
        '''Check if Email is inside DB. Return False if email doesn't exist'''
        email_check = User.query.filter_by(email=email).first()
        if email_check is None:
            return False
        return True

    @staticmethod
    def check_username(username):
        '''Check if username is available. Return True if available'''
        check_username = User.query.filter_by(username=username).first()
        if check_username is None:
            return True
        return False

    @staticmethod
    def check_passwords_match(password, confirmpassword):
        '''Return True if form passwords match'''
        if password != confirmpassword:
            return False
        return True

    @staticmethod
    def hash_password(password):
        '''Hash Password'''
        pw_encode = password.encode('utf-8')
        hashed_pw = hashlib.sha256(pw_encode).hexdigest()
        return hashed_pw

    @staticmethod
    def get_hashed_password(email):
        ''' Get hashed Password from Email in DB '''
        user = User.query.filter_by(email=email).first()
        return user.password

    @staticmethod
    def check_hashed_password(password, hashed_password):
        ''' Check is form password matches hashed pw '''
        if User.hash_password(password) != hashed_password:
            return False
        return True

    @staticmethod
    def check_account_lock(email):
        ''' Check is account is locked. Return True if locked '''
        query_user = User.query.filter_by(email=email).first()
        if query_user.lock_status:
            return True
        return False

    @staticmethod
    def check_account_status(email):
        ''' Check account is activated -> Return False if not '''
        check_status = User.query.filter_by(email=email).first()
        if not check_status.account_status:
            return False
        return True

    @staticmethod
    def check_login_ip(email, ip):
        ''' Check is userIP is in DB. If not return Call Trustedsession & return False '''
        query_user = User.query.filter_by(email=email).first()
        if query_user.reg_ip != User.userIP():
            if TrustedSession(ip).check_trusted_ip():
                return True
            return False
        return True

    @staticmethod
    def check_activation_code(code):
        ''' Check if activation code matches in DB. Else return False '''
        ''' If true, remove code from DB, update account status to True '''
        check_code = User.query.filter_by(activation_link=code).first()
        if check_code is None:
            return False

        check_code.activation_link = None
        check_code.account_status = True
        check_code.update()
        return check_code

    @staticmethod
    def add_new_user(username, email, password, reg_ip, c_date, p_img, role, activation_link):
        ''' Add new user to the DB '''
        new_user = User()
        new_user.username = username
        new_user.email = email
        new_user.password = password
        new_user.reg_ip = reg_ip
        new_user.c_date = c_date
        new_user.p_img = p_img
        new_user.role = role
        new_user.activation_link = activation_link
        new_user.add()

        return True

    @staticmethod
    def updateCodeinDB(email, verification_code, column):
        query = User.query.filter_by(email=email).first()
        setattr(query, column, verification_code)
        query.update()

    @staticmethod
    def generate_pw_reset(StringLength=20):
        pw = string.ascii_uppercase + string.ascii_lowercase + string.digits
        return ''.join(choice(pw) for i in range(StringLength))

    @staticmethod
    def check_pw_reset_code(email, code):
        query_user = User.query.filter_by(email=email).first()
        if query_user.password_reset_code == code:
            return True
        return False

    @staticmethod
    def update_pw(email, password):
        query_user = User.query.filter_by(email=email).first()
        query_user.password = User.hash_password(password)
        query_user.password_reset_code = None
        query_user.update()

    @staticmethod
    def verificationFail(email):
        ''' Append +1 to verification counter in DB. Once it reaches 3 fails, lock the account '''
        ''' Return True if account is locked '''
        query_db = User.query.filter_by(email=email).first()
        query_db.verification_fails = query_db.verification_fails + 1
        query_db.update()
        
        if query_db.verification_fails >= 3:
            query_db = User.query.filter_by(email=email).first()
            query_db.lock_status = True
            query_db.verification_fails = 0
            query_db.email_verification = None
            query_db.locked_until = str(datetime.now() + timedelta(hours=24))
            query_db.lock_status = True
            query_db.update()
            return True

        return False

    @staticmethod
    def check_if_lock_is_expired(email):
        fetch = User.query.filter_by(email=email).first()
        if fetch.locked_until is None:
            return True
        
        convert_to_datetime = datetime.strptime(fetch.locked_until, "%Y-%m-%d %H:%M:%S.%f")

        if (datetime.now() - convert_to_datetime) > timedelta(1):
            fetch.lock_status = False
            fetch.locked_until = None
            fetch.update()
            return True
        else:
            return False
        

class TrustedSession(db.Model):
    __tablename__ = 'trusted_session'
    id = db.Column(db.Integer, primary_key=True)
    userID = db.Column(db.Integer, db.ForeignKey('users.id'))
    ip = db.Column(db.String(50), primary_key=True)

    def __init__(self, ip):
        self.ip = ip

    def add(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def add_ip(self, email):
        query_user = User.query.filter_by(email=email).first()
        query_trusted_table = TrustedSession(self.ip)
        query_trusted_table.ip = self.ip
        query_trusted_table.userID = query_user.id
        query_trusted_table.add()

    def check_trusted_ip(self):
        query_ip = TrustedSession.query.filter_by(ip=self.ip).first()
        if query_ip is None:
            return False
        return True
