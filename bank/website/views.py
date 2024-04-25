from flask import Blueprint, flash, redirect, render_template, request, flash, url_for
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

        if title is None or len(title) < 3:
            flash('Transfer title is too short!', category='error')
        else:
            return redirect(url_for('views.confirmation',
                                    user=current_user,
                                    title=title,
                                    amount=amount))
            
    return render_template("new_transfer.html",
                           user=current_user)

@views.route('/confirmation', methods=['GET', 'POST'])
@login_required
def confirmation():
    title = request.args.get('title')
    amount = request.args.get('amount')

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
                                amount=new_transfer.amount))

    return render_template("confirmation.html",
                           user=current_user,
                           title=title,
                           amount=amount)

@views.route('/summary', methods=['GET'])
@login_required
def summary():
    return render_template("summary.html",
                           user=current_user,
                           title=request.args.get('title'),
                           amount=request.args.get('amount'))

@views.route('/history', methods=['GET'])
@login_required
def history():
    return render_template("history.html", user=current_user)
