from datetime import timezone

from flask_login import UserMixin
from sqlalchemy.sql import func

from . import db


class Transfer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120))
    sender = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Integer)
    date = db.Column(db.DateTime(timezone=True), default=func.now())

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    username = db.Column(db.String(120))
    password = db.Column(db.String(120))
    transfers = db.relationship('Transfer', primaryjoin='User.id == Transfer.sender', backref='user')

