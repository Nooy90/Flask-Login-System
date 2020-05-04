from flask import render_template, redirect, url_for, Blueprint, request, session
from app.forms import UserRegister, UserLoginForm, ResetPassword, SetPassword, LoginVerify
from app.models import User, TrustedSession
from app.classes import UploadedImage, EmailVerification, Emails
from app.login import current_user, already_logged_in, log_user_out
from flask_login import login_user
from datetime import datetime

auth_bp = Blueprint('auth_bp', __name__)

@auth_bp.route('/auth/register', methods=['GET'])
@already_logged_in
def user_register():
    form = UserRegister()
    return render_template('auth/register.html', form=form, message=None)

@auth_bp.route('/auth/reg_user', methods=['POST'])
@already_logged_in
def reg_user():
    form = UserRegister()
    
    if form.validate_on_submit():
        if User.check_email(request.form.get('email')):
            message = True
            return render_template('/auth/register.html', form=form, message=message)
        
        if not User.check_username(request.form.get('username')):
            message = 'Username is taken. Please try another Username'
            return render_template('/auth/register.html', form=form, message=message)

        if not User.check_passwords_match(request.form.get('password'), request.form.get('confirm_password')):
            message = 'Passwords do not match. Please try again'
            return render_template('/auth/register.html', form=form, message=message)

        
        if not UploadedImage(str(form.profile_img.data.filename)).imageCheck():
            message = 'Unsupported image format. Please upload one of the following: .JPG, .JPEG or .PNG'
            return render_template('/auth/register.html', form=form, message=message)

        generate_verification_link = EmailVerification.verifyAccountLink()
        
        User().add_new_user(username=request.form.get('username'), email=request.form.get('email'), password=User.hash_password(request.form.get('password')), reg_ip=User.userIP(), c_date=str(datetime.now()), p_img=UploadedImage.imageSave(form.profile_img.data.filename, form.profile_img.data, 'profile_images'), role=request.form.get('role'), activation_link=generate_verification_link)

        Emails(request.form.get('email')).newUserVerification(generate_verification_link)

        return redirect(url_for('auth_bp.verify_account'))

    else:
        if User().check_form_email_validation(request.form.get('email')):
            message = 'Unknown Error Occured.'
            return render_template('auth/register.html', form=form, message=message)
        
        message = 'Please enter a valid email'
        return render_template('/auth/register.html', form=form, message=message)
        
@auth_bp.route('/auth/verify-account', methods=['GET'])
@already_logged_in
def verify_account():
    return render_template('auth/verify-account.html', title="Verify Account")

@auth_bp.route('/auth/account/verification/verifyID/<code>', methods=['GET'])
@already_logged_in
def account_activation(code):
    form = UserLoginForm()
    check_activation = User.check_activation_code(code)
    
    if not check_activation:
        return redirect(url_for('auth_bp.user_login'))

    login_user(check_activation, remember=True)
    session['logged-in'] = True

    if current_user.get_role() == 'SELLER':
        return redirect(url_for('seller_bp.dashboard'))
    elif current_user.get_role() == 'BUYER':
        return redirect(url_for('buyer_bp.dashboard'))
    else:
        logout_user()
        session.clear()
        return redirect(url_for('auth_bp.user_login'))

@auth_bp.route('/auth/login', methods=['GET'])
@already_logged_in
def user_login():
    form = UserLoginForm()
    return render_template('auth/login.html', form=form, title="Login")

@auth_bp.route('/auth/loginAttempt', methods=['POST'])
def user_login_attempt():
    form = UserLoginForm()
    email = request.form.get('email')
    login_ip = User.userIP()

    if form.validate_on_submit():
        if not User.check_email(email):
            message = 'Incorrect login details'
            return render_template('auth/login.html', message=message, form=form, title="Login")

        if not User.check_hashed_password(request.form.get('password'), User.get_hashed_password(email)):
            User().verificationFail(email)
            message = 'Incorrect login details'
            return render_template('auth/login.html', message=message, form=form, title="Login")            
        
        if not User.check_account_status(email): 
            generate_new_verfication_code = EmailVerification(email).verifyAccountLink()

            Emails(request.form.get('email')).newUserVerification(generate_new_verfication_code)
            
            User().updateCodeinDB(request.form.get('email'), generate_new_verfication_code, 'activation_link')

            message = 'Your account has not been verified. Another email has been sent'
            return render_template('auth/login.html', form=form, message=message, title="Login")

        if User.(email):
            if User.check_ifcheck_account_lock_lock_is_expired(email):
                pass
            else:
                account_locked = Emails(email).accountLocked()
                message = 'Account Locked'
                return render_template('/auth/login.html', form=form, message=message, title="Login")
        
        if User.check_login_ip(email, login_ip):
            user_to_login = User.query.filter_by(email=email).first()
            login_user(user_to_login, remember=True)
            session['logged-in'] = True

            if current_user.get_role() == 'BUYER':
                return redirect(url_for('buyer_bp.dashboard'))
            elif current_user.get_role() == 'SELLER':
                return redirect(url_for('seller_bp.dashboard'))
            else:
                logout_user()
                return redirect('auth_bp.user_login')
        else:
            session['email'] = email
            session['ip'] = login_ip
            generate_verification_code = EmailVerification(email).emailVerificationCode()
            Emails(request.form.get('email')).sendVerificationEmail(User().userIP(), generate_verification_code)

            User.updateCodeinDB(session['email'], generate_verification_code, 'email_verification')

            return redirect(url_for('auth_bp.verify_new_ip'))

    else:
        if not User().check_form_email_validation(request.form.get('email')):
            message = 'Invalid Login Details'
            return render_template('auth/login.html', message=message, form=form, title="Login")
        
        message = 'Unknown Error Occured'
        return render_template('auth/login.html', message=message, form=form, title="Login")

@auth_bp.route('/auth/verify', methods=['GET'])
@already_logged_in
def verify_new_ip():
    form = LoginVerify()

    return render_template('auth/verify-ip.html', form=form, title="Email Verification")

@auth_bp.route('/auth/verify/ip', methods=['POST'])
@already_logged_in
def confirm_email_code():
    form = LoginVerify()
    if form.validate_on_submit():
        if EmailVerification(session['email']).check_email_code(request.form.get('email_code')) is True:
            EmailVerification(session['email']).delete_email_verification_code()
            TrustedSession(session['ip']).add_ip(session['email'])

            user_login = User.query.filter_by(email=session['email']).first()
            login_user(user_login, remember=True)
            session['logged-in'] = True
            session.pop('email')
            session.pop('ip')
            
            if current_user.get_role() == 'SELLER':
                return redirect(url_for('seller_bp.dashboard'))
            elif current_user.get_role() == 'BUYER':
                return redirect(url_for('buyer_bp.dashboard'))
            else:
                logout_user()
                return redirect(url_for('auth_bp.login'))


        if User(session['email']).verificationFail():
            return redirect(url_for('auth_bp.user_login'))
        else:
            message = 'Invalid Code Entered. Please try again'
            return render_template('auth/verify-ip.html', form=form, message=message, title="Email Verification")
    
    else:
        message = 'Error Occured. Please try again later'
        return render_template('auth/verify-ip.html', form=form, message=message, title="Email Verification")

@auth_bp.route('/auth/resend-email-verification', methods=['GET'])
@already_logged_in
def resend_verification_code():
    form = LoginVerify()

    regenerate_email_verification = EmailVerification(session['email']).emailVerificationCode()
    User.updateCodeinDB(session['email'], regenerate_email_verification, 'email_verification')

    Emails(session['email']).sendVerificationEmail(session['ip'], regenerate_email_verification)
    
    message = 'New verification code has been emailed.'
    return render_template('auth/verify-ip.html', form=form, message=message, title="Email Verification")

@auth_bp.route('/auth/forgotten-password', methods=['GET'])
@already_logged_in
def forgotten_password():
    form = ResetPassword()
    return render_template('auth/forgotten-password.html', form=form, title="Forgotten Password")
    
@auth_bp.route('/auth/submit-password-reset', methods=['POST'])
@already_logged_in
def password_reset():
    form = ResetPassword()
    session['email'] = request.form.get('email')
    if form.validate_on_submit():
        if not User.check_form_email_validation(session['email']):
            message = 'Invalid Email Address'
            return render_template('auth/forgotten-password.html', form=form, message=message, title="Forgotten Password")

        if not User.check_email(session['email']):
            message = 'Invalid Email Address'
            return render_template('auth/forgotten-password.html', form=form, message=message, title="Forgotten Password")

        pw_reset_code = User.generate_pw_reset()
        User.updateCodeinDB(session['email'], pw_reset_code, 'password_reset_code')

        Emails(session['email']).resetPassword(pw_reset_code)

        session['password_authorisation'] = True
        
        message = 'Password reset link has been emailed. Please check your email.'
        return render_template('auth/password-email-sent.html', message=message, form=form, title="Password Reset")

    if not User.check_form_email_validation():
        message = 'Invalid Email'
        return render_template('/auth/forgotten-password.html', form=form, message=message)

    message = 'Something went wrong. Please try again later'
    return render_template('/auth/forgotten-password.html', form=form, message=message)

@auth_bp.route('/auth/password/reset/<code>', methods=['GET'])
@already_logged_in
def pw_reset(code):
    form = SetPassword()
    if 'email' in session and 'password_authorisation' in session:
        if session['password_authorisation'] and User.check_pw_reset_code(session['email'], code):
            return render_template('auth/set-new-password.html', form=form)
    return redirect(url_for('auth_bp.login'))

@auth_bp.route('/auth/set-password', methods=['POST'])
@already_logged_in
def update_password():
    form = SetPassword()

    if form.validate_on_submit():
        if 'password-authorisation' not in session:
            redirect(url_for('auth_bp.forgotten_password'))
        
        User.update_pw(session['email'], request.form.get('password'))
        session.pop('password_authorisation')
        session.pop('email')

        return redirect(url_for('auth_bp.user_login'))

    if len(request.form.get('password')) < 10:
        message = 'Password Length too short'
        return render_template('auth/set-new-password.html', form=form, message=message, title="Reset Password")

    message = 'Unknown error. Please try again later'
    return render_template('auth/set-new-password.html', form=form, message=message, error="Reset Password")

@auth_bp.route('/auth/logout', methods=['GET'])
@log_user_out
def logout():
    session.clear()
    return redirect(url_for('auth_bp.user_login'))
