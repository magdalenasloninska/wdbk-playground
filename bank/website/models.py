from flask_login import UserMixin
from sqlalchemy.sql import func
import pyotp

from . import db, APP_NAME


class Transfer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120))
    sender = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Integer)
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    is_executed = db.Column(db.Boolean, default=False)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    username = db.Column(db.String(120))
    password = db.Column(db.String(120))
    transfers = db.relationship('Transfer', primaryjoin='User.id == Transfer.sender', backref='user')
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    secret_token = db.Column(db.String, unique=True)
    is_bank_admin = db.Column(db.Boolean, default=False)

    def get_authentication_setup_uri(self):
        return pyotp.totp.TOTP(self.secret_token).provisioning_uri(
                name=self.username,
                issuer_name=APP_NAME)

    def is_otp_valid(self, user_otp):
        totp = pyotp.parse_uri(self.get_authentication_setup_uri())
        return totp.verify(user_otp)

