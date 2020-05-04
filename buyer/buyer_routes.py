from flask import Blueprint
from app.login import login_required, buyer_required

buyer_bp = Blueprint('buyer_bp', __name__)

@buyer_bp.route('/buyer/dashboard', methods=['GET'])
@login_required
@buyer_required
def dashboard():
    return 'buyer dashboard'
