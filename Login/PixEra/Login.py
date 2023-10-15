import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
import random
import string
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = Flask(__name__)

mongo_client = MongoClient(os.getenv("MONGO_URL"), server_api=ServerApi('1'))
db = mongo_client['PixEraDB']

# MongoDB collection for user data
users_collection = db['Users']

# Store reset tokens and their corresponding email
reset_tokens = {}


@app.route('/')
def home():
    return 'Welcome to the Flask Login System'


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if users_collection.find_one({'email': email}):
            flash('Email already registered. Please log in.')
            return redirect(url_for('login'))

        user_data = {'email': email, 'password': password}
        users_collection.insert_one(user_data)
        flash('Account created successfully. Please log in.')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = users_collection.find_one({'email': email, 'password': password})

        if user:
            flash('Login successful!')
            return redirect(url_for('home'))
        else:
            flash('Login failed. Please check your email and password.')

    return render_template('login.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = users_collection.find_one({'email': email})

        if user:
            # Generate a random reset token
            token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))
            reset_tokens[token] = email

            # Send a reset email with a link using SendGrid
            reset_link = url_for('reset_password', token=token, _external=True)
            message = Mail(
                from_email='dev.pixera@gmail.com',
                to_emails=[email],
                subject='Password Reset',
                plain_text_content=f'To reset your password, click the following link: {reset_link}'
            )

            try:
                sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
                response = sg.send(message)
                flash('Password reset instructions sent to your email.')
            except Exception:
                flash('Failed to send the reset email.')
        else:
            flash('Email not found.')
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if token in reset_tokens:
        email = reset_tokens[token]
        if request.method == 'POST':
            new_password = request.form['new_password']
            users_collection.update_one({'email': email}, {'$set': {'password': new_password}})
            flash('Password reset successfully. You can now log in with your new password.')
            del reset_tokens[token]
            return redirect(url_for('login'))
        return render_template('reset_password.html')
    else:
        flash('Invalid or expired token.')
        return redirect(url_for('forgot_password'))


if __name__ == '__main__':
    app.secret_key = os.getenv("SECRET_KEY")
    app.run(debug=True, host = "localhost", port = 3000)
