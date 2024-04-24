from flask import Blueprint, flash, render_template, request, flash
from flask_login import login_required, current_user

from .models import Transfer
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
        amount = request.form.get('amount')

        if len(title) < 3:
            flash('Transfer title is too short!', category='error')
        else:
            new_transfer = Transfer(
                    title=title,
                    sender=current_user.id,
                    amount=amount)
            db.session.add(new_transfer)
            db.session.commit()

    return render_template("new_transfer.html", user=current_user)

@views.route('/history', methods=['GET'])
@login_required
def history():
    return render_template("history.html", user=current_user)
