from flask import Blueprint, flash, redirect, render_template, request, flash, url_for
from flask_login import login_required, current_user

from .models import Transfer
from .utils import get_b64encoded_qr_image
from . import db


views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    return render_template("home.html", user=current_user)

@views.route('/new-transfer', methods=['GET', 'POST'])
@login_required
def new_transfer():
    if request.method == 'POST':
        title = request.form.get('title')
        amount = int(request.form.get('amount', 0))
        recipient = request.form.get('recipient')

        if title is None or len(title) < 3:
            flash('Transfer title is too short!', category='error')
        elif amount < 0 or amount > 1000:
            flash('The maximum amount is 1000 units!', category='error')
        elif recipient is None or len(recipient) < 1:
            flash('You must enter a recipient!', category='error')
        else:
            return redirect(url_for('views.confirmation',
                                    user=current_user,
                                    title=title,
                                    amount=amount,
                                    recipient=recipient))
            
    return render_template("new_transfer.html",
                           user=current_user)

@views.route('/confirmation', methods=['GET', 'POST'])
@login_required
def confirmation():
    title = request.args.get('title')
    amount = request.args.get('amount')
    recipient = request.args.get('recipient')

    if request.method == 'POST':

        new_transfer = Transfer(
                title=title,
                sender=current_user.id,
                amount=amount)
        
        db.session.add(new_transfer)
        db.session.commit()

        return redirect(url_for('views.summary',
                                user=current_user,
                                title=new_transfer.title,
                                amount=new_transfer.amount,
                                recipient=recipient))

    return render_template("confirmation.html",
                           user=current_user,
                           title=title,
                           amount=amount,
                           recipient=recipient)

@views.route('/summary', methods=['GET'])
@login_required
def summary():
    return render_template("summary.html",
                           user=current_user,
                           title=request.args.get('title'),
                           amount=request.args.get('amount'),
                           recipient=request.args.get('recipient'))

@views.route('/history', methods=['GET'])
@login_required
def history():
    return render_template("history.html", user=current_user)

@views.route('/setup-2fa')
@login_required
def setup_2fa():
    secret = current_user.secret_token
    uri = current_user.get_authentication_setup_uri()
    base64_qr_image = get_b64encoded_qr_image(uri)
    return render_template("setup_2fa.html", user=current_user, secret=secret, qr_image=base64_qr_image)

@views.route('/verify-2fa-token', methods=['GET', 'POST'])
def verify_2fa_token():
    otp = request.form.get('otp', '')
    if len(otp) == 6:
        if current_user.is_otp_valid(otp):
            if current_user.is_2fa_enabled:
                flash("2FA verification successful. You are logged in!", category="success")
                return redirect(url_for('views.home'))
            else:
                try:
                    current_user.is_2fa_enabled = True
                    db.session.commit()
                    flash("2FA setup successful. You are logged in!", category="success")
                    return redirect(url_for('views.home'))
                except Exception:
                    db.session.rollback()
                    flash("2FA setup failed. Please try again.", category="danger")
                    return redirect(url_for('views.verify_2fa_token'))
        else:
            flash("Invalid OTP. Please try again.", category="danger")
            return redirect(url_for('views.verify_2fa_token'))
    else:
        if not current_user.is_2fa_enabled:
            flash(
                "You have not enabled 2-Factor Authentication. Please enable it first.", category="info")
        return render_template("verify_2fa_token.html", user=current_user, form=request.form)
