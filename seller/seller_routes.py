from flask import Blueprint
from app.login import login_required, seller_required


seller_bp = Blueprint('seller_bp', __name__)

@seller_bp.route('/seller/dashboard', methods=['GET'])
@login_required
@seller_required
def dashboard():
    return 'seller dashboard'
