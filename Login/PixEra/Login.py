import os

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_user import UserManager, current_user
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config['MONGO_URI'] = os.getenv("MONGO_URL")
mongo = PyMongo(app)
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

app.config['MAIL_SERVER'] = 'smtp.your-email-provider.com' ##configs to send mail to user
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

class User(UserMixin):
    def __init__(self, user_id, reset_token=None, reset_token_expiration=None):
        self.id = user_id
        self.reset_token = reset_token
        self.reset_token_expiration = reset_token_expiration

    def is_reset_token_valid(self): ##if reset token expires
        if self.reset_token_expiration:
            return self.reset_token_expiration > datetime.now()
        return False

user_manager = UserManager(app, mongo, User)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a reset token
            reset_token = user_manager.generate_reset_password_token(user)

            # Send an email with the reset link
            send_reset_email(user, reset_token)
            flash('An email with instructions for resetting your password has been sent.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email address not found.', 'danger')

    return render_template('forgot_password.html')

def send_reset_email(user, token): ##send reset password email
    reset_link = url_for('reset_password', token=token, _external=True)
    subject = 'Password Reset Request'
    body = f'Click the following link to reset your password: {reset_link}'
    msg = Message(subject, recipients=[user.email], body=body)
    mail.send(msg)


@app.route('/register', methods=['GET', 'POST']) ##users to register through our app and not Google
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        existing_user = mongo.db.users.find_one({'username': username})

        if existing_user:
            flash('Username already exists. Choose a different one.', 'danger')
        else:
            hashed_password = generate_password_hash(password, method='sha256')
            mongo.db.users.insert({'username': username, 'email': email, 'password': hashed_password})
            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST']) ##User login router
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = mongo.db.users.find_one({'username': username}) ##check if user exists

        if user and check_password_hash(user['password'], password): ##check hashed password
            user_obj = User(username)
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html') ##should lead to login template (not created yet)

@app.route('/dashboard') ##take to dashboard
@login_required
def dashboard():
    return f'Hello, {current_user.id}! This is your dashboard.'

@app.route('/logout') ##logout if logged in
@login_required
def logout():
    logout_user()
    return redirect(url_for('login')) ##take back to login screen if logged out

if __name__ == '__main__':
    app.run(debug=True, host = "localhost", port = 3000)
