import json

from flask import Blueprint, redirect, render_template, request, flash, url_for, session
from flask_login import login_user, login_required, logout_user, current_user
from argon2.exceptions import VerifyMismatchError
import requests
import pyotp
import uuid

from .models import User
from . import db, ph, client, get_google_provider_cfg, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()

        if user:
            try:
                ph.verify(user.password, password)
                var_2fa = user.is_2fa_enabled

                if var_2fa:
                    return redirect(url_for('auth.verify_2fa_token', email=email))
                else:
                    flash('Logged in successfully!', category='success')
                    login_user(user)
                    return redirect(url_for('views.home', activate=True))
            except VerifyMismatchError:
                flash('Incorrect password, try again.', category='error')
            except Exception as e:
                print(e)
                flash('Unknown error, please contact the admin.', category='error')
        else:
            flash("User doesn't exist.", category='error')
    
    return render_template("login.html", user=current_user)


@auth.route('/verify-2fa-token', methods=['GET', 'POST'])
def verify_2fa_token():
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first()

    if current_user.is_authenticated:
        user = current_user

    if request.method == 'POST':
        otp = request.form.get('otp', '')

        if len(otp) == 6 and user.is_otp_valid(otp):
            if user.is_2fa_enabled:
                login_user(user, remember=True)
                # TODO: Add sessionStorage here as well!
                flash("Logged in successfully (via 2FA)!", category='success')
                return redirect(url_for('views.home'))
            else:
                try:
                    user.is_2fa_enabled = True
                    db.session.commit() 
                    flash("2FA setup is done!", category='success')
                    return redirect(url_for('views.home', user=user))
                except Exception:
                    db.session.rollback()
                    flash("2FA setup failed. Please try again.", category='error')
                    return redirect(url_for('auth.verify_2fa_token'))
        else:
            flash("Invalid OTP. Please try again.", category='error')
            return redirect(url_for('auth.verify_2fa_token', email=email))

    return render_template("verify_2fa_token.html", user=current_user, email=email)

@auth.route('/google-login')
def google_login():

    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@auth.route("/google-login/callback")
def callback():
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code)

    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET))

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        users_email = userinfo_response.json()["email"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    google_user = User(
            username=users_name,
            email=users_email,
            secret_token = pyotp.random_base32())

    user = User.query.filter_by(email=google_user.email).first()

    if not user:
        db.session.add(google_user)
        db.session.commit()
        flash('Account created (via Google)!', category='success')
        user = User.query.filter_by(email=google_user.email).first()

    login_user(user)
    
    return redirect(url_for('views.home'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        admin = request.form.get('admin') == 'on'
        
        user = User.query.filter_by(email=email).first()

        if user:
            flash('User already exists.', category='error')
        elif password1 != password2:
            flash("Passwords don't match!", category='error')
        else:
            new_user = User(
                    email=email,
                    username=username,
                    password=ph.hash(password1),
                    secret_token=pyotp.random_base32(),
                    is_bank_admin=admin)

            db.session.add(new_user)
            db.session.commit()
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)
