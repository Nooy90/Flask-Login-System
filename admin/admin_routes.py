from app.forms import AdminRegister, AdminLogin, LoginVerify
from app.classes import UploadedImage, Emails, EmailVerification
from app.models import User, TrustedSession
from datetime import datetime, timedelta
from app.login import admin_login_required, login_required, log_user_out, already_logged_in
from flask_login import login_user
from flask import session, request, url_for, Flask, render_template, Blueprint, redirect

admin_bp = Blueprint('admin_bp', __name__)

@admin_bp.route('/admin/setup', methods=['GET'])
@already_logged_in
def admin_setup():
    if User.check_for_admin():
        if not User.check_admin_ip(User.userIP()):
            return redirect(url_for('admin_bp.restricted_access', remoteIP=User.userIP()))

        return redirect(url_for('admin_bp.admin_login'))
    
    form = AdminRegister()
    return render_template('admin/setup.html', form=form, title='Admin Setup')

@admin_bp.route('/admin/register', methods=['POST'])
@already_logged_in
def admin_register():
    form = AdminRegister()

    if form.validate_on_submit():
        if not User.check_passwords_match(request.form.get('password'), request.form.get('confirm_password')):
            error = 'Passwords do not match'
            return render_template('admin/setup.html', form=form, error=error, title="Admin Register")
        
        if not UploadedImage(imageName=form.profile_img.data.filename).imageCheck():
            error = 'Invalid Profile Image. Please upload a profile image with .JPG, .JPEG or .PNG format'
            return render_template('admin/setup.html', error=error, form=form, title="Admin Register")

        User.add_new_user(email=request.form.get('email'), username='admin', password=User.hash_password(request.form.get('password')), c_date=str(datetime.now().date()), p_img=UploadedImage.imageSave(form.profile_img.data.filename, form.profile_img.data, 'profile_images'), reg_ip=User.userIP(), role="ADMIN", activation_link=None)

        user_to_login = User.query.filter_by(email=request.form.get('email')).first()

        login_user(user_to_login, remember=True)
        return redirect(url_for('admin_bp.dashboard'))
        
    if not User.check_form_email_validation(request.form.get('email')):
        error = 'Invalid Email'
        return render_template('admin/setup.html', form=form, error=error, title="Admin Register")

    if len(request.form.get('admin_password')) < 8:
        error = 'Password to short'
        return render_template('admin/setup.html', form=form, error=error, title="Admin Register")

    else:
        error = 'Unknown Error Occured.'
        return render_template('setup.html', form=form, error=error, title="Admin Register")

@admin_bp.route('/<remoteIP>', methods=['GET'])
def restricted_access(remoteIP):
    remoteIP = User.userIP()
    admin = User.query.filter_by(role='ADMIN').first()
    emails_obj = Emails(admin.email).unauthorised_access(remoteIP)
    return render_template('admin/restricted.html', ip=remoteIP)

@admin_bp.route('/admin/login', methods=['GET'])
@already_logged_in
def admin_login():
    form = AdminLogin()
    return render_template('admin/admin-login.html', form=form, title="Admin Login")

@admin_bp.route('/admin/loginAttempt', methods=['POST'])
def admin_login_attempt():
    form = AdminLogin()
    email = request.form.get('email')
    if not User.check_if_admin(email):
        error = 'Invalid Login Details'
        return render_template('admin/admin-login.html', form=form, error=error, title="Admin Login")

    if not User.check_hashed_password(request.form.get('password'), User.get_hashed_password(email)):
        error = 'Invalid Login Details'
        return render_template('admin/admin-login.html', form=form, error=error, title="Admin Login")

    if not User.check_login_ip(email, User.userIP()):

        generated_email_code = EmailVerification.emailVerificationCode()
        User.updateCodeinDB(email, generated_email_code, 'email_verification')
        Emails(email).sendVerificationEmail(User.userIP(), generated_email_code)
        
        session['verify-email'] = True
        session['email'] = email
        session['ip'] = User.userIP()
        
        return redirect(url_for('admin_bp.login_verification'))

    user_to_login = User.query.filter_by(email=email).first()
    session['logged-in'] = True
    login_user(user_to_login, remember=True)
    
    return redirect(url_for('admin_bp.dashboard'))

@admin_bp.route('/admin/login-verification', methods=['GET'])
@already_logged_in
def login_verification():
    form = LoginVerify()
    return render_template('admin/login-verification.html', form=form, title="Verify Login")

@admin_bp.route('/check-verification-code', methods=['POST'])
def verification_check():
    form = LoginVerify()
    email_code = request.form.get('email_code')
    
    if form.validate_on_submit():
        if 'verify-email' not in session or not session['verify-email']:
            return redirect(url_for('auth_bp.admin_login'))
        if EmailVerification(session['email']).check_email_code(email_code):
            User.updateCodeinDB(session['email'], None, 'email_verification')

            TrustedSession(ip=session['ip']).add_ip(session['email'])

            user_to_login = User.query.filter_by(email=session['email']).first()

            session.pop('verify-email')
            session.pop('ip')
            session.pop('email')
            
            login_user(user_to_login, remember=True)
            
            return redirect(url_for('admin_bp.dashboard'))
    
        else:
            error = 'Sorry! Your code is incorrect. Please Try Again'
            return render_template('admin/login-verification.html', form=form, error=error, title="Verify Login")

    error = 'An error occured. Please try again later'
    return render_template('admin/login-verification.html', form=form, error=error, title="Verify Login")

@admin_bp.route('/admin/resend-verification/', methods=['GET'])
@already_logged_in
def resend_verification():
    regenerate_email_code = EmailVerification.emailVerificationCode()
    User.updateCodeinDB(session['email'], regenerate_email_code, 'email_verification')
    Emails(session['email']).sendVerificationEmail(session['ip'], regenerate_email_code)

    return redirect(url_for('admin_bp.login_verification'))

@admin_bp.route('/check-verification-code', methods=['GET'])
def verification_no_access():
    return redirect(url_for('admin_bp.admin_login'))

@admin_bp.route('/admin/logout', methods=['GET'])
@admin_login_required
@log_user_out
def admin_logout():
    session.clear()
    return redirect(url_for('admin_bp.admin_login'))

@admin_bp.route('/admin/dashboard', methods=['GET'])
@admin_login_required
@login_required
def dashboard():
    return render_template('admin/dashboard.html')
