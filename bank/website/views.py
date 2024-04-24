from flask import Blueprint, flash, render_template, request, flash
from flask_login import login_required, current_user

from .models import Transfer
from . import db


views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        title = request.form.get('title')

        if len(title) < 3:
            flash('Transfer title is too short!', category='error')
        else:
            new_transfer = Transfer(title=title, sender=current_user.id)
            db.session.add(new_transfer)
            db.session.commit()
            flash('Transfer sent!', category='success')

    return render_template("home.html", user=current_user)
