import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
import random
import string
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import pyotp
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

mongo_client = MongoClient(os.getenv("MONGO_URL"), server_api=ServerApi('1'))
db = mongo_client['PixEraDB']
users_collection = db['Users']

# Store reset tokens and their corresponding email
reset_tokens = {}

totp_secret = os.getenv("TOTP_SECRET")

@app.route('/home')
def home():
    return 'Welcome to the Flask Login System'

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not email:
            flash('Email is required.')
            return redirect(url_for('signup'))
        
        # Check if the user already exists
        user = users_collection.find_one({'email': email})
        
        if user:
            # Hash the password using bcrypt
            hashed_password = bcrypt.generate_password_hash(password).decode(os.getenv("DECODE_ALGORITHM"))
            if user["password"] == "":
                # Update the user's password
                users_collection.update_one({'email': email}, {'$set': {'password': hashed_password}})
                flash('Password updated successfully.')
                return redirect(url_for('login'))
            elif bcrypt.check_password_hash(user['password'], password):
                flash("user already has an account. Please log in")
                return redirect(url_for('login'))
        else:
            if not password:
                flash('Password is required.')
                return redirect(url_for('signup'))
            
            # Hash the password using bcrypt
            hashed_password = bcrypt.generate_password_hash(password).decode(os.getenv("DECODE_ALGORITHM"))
            user_data = {'email': email, 'password': hashed_password}

            # Store the user in the database
            users_collection.insert_one(user_data)
            flash('Account created successfully. Please log in.')
            return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users_collection.find_one({'email': email})
        
        if user:
            # Check if the password field is not empty
            if not password:
                flash('Password cannot be empty. Please provide a password.')
                return redirect(url_for('login'))
            
            # Verify the password using check_password_hash
            if user["password"] != "":
                if bcrypt.check_password_hash(user['password'], password):
                    # The password is verified
                    totp = pyotp.TOTP(totp_secret)
                    token = totp.now()
                    
                    # Send the TOTP token to the user's email
                    message = Mail(
                        from_email='dev.pixera@gmail.com',
                        to_emails=[email],
                        subject='Two-Factor Authentication',
                        plain_text_content=f'Your TOTP token is: {token}'
                    )
                    
                    try:
                        sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
                        response = sg.send(message)
                        flash('A TOTP token has been sent to your email. Please check your email and enter the token.')
                    except Exception:
                        flash('Failed to send the TOTP token.')
                    
                    # Redirect to the 2FA verification page
                    return redirect(url_for('verify_2fa', email=email))
            else:
                flash('Login failed. Please check your email and password.')
                return render_template('login.html')
        else:
            flash('User not found. Please check your email and try again.')
    
    return render_template('login.html')

@app.route('/resend_2fa/<email>', methods=['GET', 'POST'])
def resend_2fa(email):
    if request.method == 'GET':
        # Resend the TOTP token to the user's email
        totp = pyotp.TOTP(totp_secret)
        token = totp.now()
        message = Mail(
            from_email='dev.pixera@gmail.com',
            to_emails=[email],
            subject='Two-Factor Authentication',
            plain_text_content=f'Your TOTP token is: {token}'
        )
        
        try:
            sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
            response = sg.send(message)
            flash('A new TOTP token has been sent to your email. Please check your email and enter the token.')
        except Exception:
            flash('Failed to resend the TOTP token.')
    
    return redirect(url_for('verify_2fa', email=email))

@app.route('/verify_2fa/<email>', methods=['GET', 'POST'])
def verify_2fa(email):
    if request.method == 'POST':
        totp_token = request.form['totp_token']
        totp = pyotp.TOTP(totp_secret)
        
        if totp.verify(totp_token):
            flash('2FA verification successful! You are now logged in.')
            return redirect(url_for('home'))
        else:
            flash('2FA verification failed. Please check the TOTP token.')
    
    return render_template('verify_2fa.html', email=email)

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
            
            if not new_password:
                flash('Password is required.')
                return redirect(url_for('reset_password', token=token))
            
            # Hash the new password
            hashed_password = bcrypt.generate_password_hash(new_password).decode(os.getenv("DECODE_ALGORITHM"))
            
            # Update the user's password in the database
            users_collection.update_one({'email': email}, {'$set': {'password': hashed_password}})
            
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