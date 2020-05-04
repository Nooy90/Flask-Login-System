from flask import abort, g, redirect, url_for, request, session
from functools import wraps
from flask_login import LoginManager, current_user
from app.models import User

login_manager = LoginManager()
login_manager.login_view = 'login'

## User Call back

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

## Login Decorators

def admin_login_required(a):
    @wraps(a)
    def decorator(*args, **kwargs):
        if current_user.is_authenticated is False:
            return redirect(url_for('admin_bp.admin_login', next=request.url))
        if 'logged-in' in session and not session['logged-in'] or 'logged-in' not in session:
            return redirect(url_for('admin_bp.admin_login'))
        return a(*args, **kwargs)
    return decorator

def login_required(l):
    @wraps(l)
    
    def decorator(*args, **kwargs):
        if 'logged-in' not in session:
            return redirect(url_for('auth_bp.user_login', next=request.url))
        if not session['logged-in']:
            return redirect(url_for('auth_bp.user_login', next=request.url))
        return l(*args, **kwargs)
    return decorator

## Page Restrictions

def admin_required(a):
    @wraps(a)
    def decorator(*args, **kwargs):
        if current_user.role() == "ADMIN":
            return a(*args, **kwargs)
        else:
            abort(401)
    return decorator

def buyer_required(b):
    @wraps(b)
    def decorator(*args, **kwargs):
        if current_user.get_role() == 'BUYER':
            return b(*args, **kwargs)
        else:
            abort(401)
    return decorator

def seller_required(s):
    @wraps(s)
    def decorator(*args, **kwargs):
        if current_user.role == 'SELLER':
            return s(*args, **kwargs)
        else:
            return abort(401)

    return decorator

def already_logged_in(a):
    @wraps(a)
    def decorator(*args, **kwargs):

        if 'logged-in' in session and session['logged-in']:
            if current_user.get_role() == 'SELLER':
                return redirect(url_for('seller_bp.dashboard'))
            if current_user.get_role() == 'BUYER':
                return redirect(url_for('buyer_bp.dashboard'))
            if current_user.get_role() == 'ADMIN':
                return redirect(url_for('admin_bp.dashboard'))
        return a(*args, **kwargs)
    return decorator

def log_user_out(l):
    @wraps(l)
    def decorator(*args, **kwargs):
        session['logged-in'] = False
        return l(*args, **kwargs)
    return decorator