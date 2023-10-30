from datetime import timedelta
import datetime
import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_mail import Mail, Message
import random
import string
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import pyotp
from flask_bcrypt import Bcrypt
import pathlib
import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from concurrent.futures import ThreadPoolExecutor
import jwt
import time

app = Flask(__name__)
bcrypt = Bcrypt(app)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

mongo_client = MongoClient(os.getenv("MONGO_URL"), server_api=ServerApi('1'))
db = mongo_client['PixEraDB']
users_collection = db['Users']

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost:3000/callback"
)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

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
        captcha_checked = request.form.get('captcha_checkbox')  # Check if the checkbox is checked

        if not captcha_checked:
            flash("Please complete the CAPTCHA.")
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
            else:
                flash("User already exists")
                return redirect(url_for('login'))
        else:
            users_collection.create_index("expirationDate", expireAfterSeconds=0)

            # Insert a document with an expiration date
            # The document will be automatically deleted after the expiration date has passed.
            expiration_date = datetime.utcnow() + timedelta(seconds=120)  # Set the expiration date to one hour from now
            # Hash the password using bcrypt
            hashed_password = bcrypt.generate_password_hash(password).decode(os.getenv("DECODE_ALGORITHM"))
            user_data = {'email': email, 'password': hashed_password, "expirationDate": expiration_date}

            # Store the user in the database
            users_collection.insert_one(user_data)
            flash('Account created successfully. Please log in.')
            return redirect(url_for('resend_2fa', email=email))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users_collection.find_one({'email': email})
        
        if user:
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
        user = users_collection.find_one({'email': email})
        totp_token = request.form['totp_token']
        totp = pyotp.TOTP(totp_secret) 
        if totp.verify(totp_token):
            password = user["password"]
            flash('2FA verification successful! You are now logged in.')
            users_collection.update_one({'email': email}, {'$unset': {'expirationDate': 1}})
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

@app.route("/login_user")
def login_user():
    authorization_url, state = flow.authorization_url()
    print(authorization_url)
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    print("came to callback")
    auth_token = flow.fetch_token(authorization_response=request.url)

    def validate_and_get_id_info():
        id_info = auth_token
        credentials = flow.credentials
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(session=cached_session)

        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID
        )

        return id_info

    with ThreadPoolExecutor() as executor:
        id_info = executor.submit(validate_and_get_id_info).result()

    # Get user's Gmail email
    user_email = id_info.get("email")

    # Check if the user already exists in the database
    users_collection = db["Users"]  # Replace with your collection name
    existing_user = users_collection.find_one({"email": user_email})

    if not existing_user:
        # If the user doesn't exist, save their information to MongoDB
        user_data = {
            "google_id": id_info.get("sub"),
            "email": user_email,
            "password": ""
        }
        users_collection.insert_one(user_data)

    # Create a JWT token and include claims, including "exp" for expiration
    expiration_time = int(time.time()) + 3600  # 1 hour from now
    user_info = {
        "google_id": id_info.get("sub"),
        "exp": expiration_time
    }
    jwt_token = jwt.encode(user_info, JWT_SECRET_KEY, algorithm=os.getenv("HASH"))

    # Redirect to localhost:5000/login with the token as a query parameter
    return redirect(f'http://localhost:5000/?token={jwt_token}')


@app.route("/logout")
def logout():
    # There's no need to clear JWT tokens as they are stateless
    return redirect("/")

@app.route("/")
def index():
    return "Welcome to PixEra <a href='/login_user'><button>Login</button></a>"

@app.route("/verify", methods=["POST"])  # Use POST method to send the JWT token in the request body
def verify():
    data = request.get_json()  # Read the JSON request body
    token = data.get("token")  # Extract the JWT token from the JSON data

    try:
        decoded_token = jwt.decode(token, JWT_SECRET_KEY, algorithms=[os.getenv("HASH")])
        expire = decoded_token.get('exp', 0)
        
        if time.time() > expire:
            return "Token has expired", 401
        else:
            return decoded_token
    except jwt.DecodeError:
        return "Invalid token", 401

if __name__ == '__main__':
    app.secret_key = os.getenv("SECRET_KEY")
    app.run(host = "localhost", port = 3000)