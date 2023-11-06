from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify
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
import os
from flask import Blueprint

login = Blueprint("login", __name__)

# @login.route('/')
# @login.route('/home')
# @login.route('/signup')
# @login.route('/login')
# @login.route('/forgot_password')
# @login.route('/reset_password/<token>')
# @login.route('/verify2FA/<email>')
# @login.route('/verify2FA_signup/<email>')
# @login.route('/photographer/<name>')
# @login.route('/photographer/<name>/<photoid>')

# def index_file(**kwarg):
#     return app.send_static_file('index.html')

# Define your environment variables here
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
TOTP_SECRET = os.getenv("TOTP_SECRET")

mongo_client = MongoClient(os.getenv("MONGO_URL"), server_api=ServerApi('1'))
db = mongo_client['PixEraDB']
users_collection = db['Users']

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost:3000/callback"
)

# Store reset tokens and their corresponding email
reset_tokens = {}
store_totp = {}

@login.route('/signup_user', methods=['POST'])
def signup():
    email = request.form['email']
    password = request.form['password']
    captcha_checked = request.form.get('captcha_checkbox')  # Check if the checkbox is checked
    role = request.form.get('role')  # Get the role from the form

    if not captcha_checked:
        return jsonify({'message': 'Please complete the CAPTCHA.'}), 400

    # Check if the user already exists
    user = users_collection.find_one({'email': email})

    if user:
        # Hash the password using bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode(os.getenv("DECODE_ALGORITHM"))
        if user["password"] == "":
            # Update the user's password and role
            users_collection.update_one({'email': email}, {'$set': {'password': hashed_password, 'role': role}})
            return jsonify({'message': 'Password updated successfully.'})

        return jsonify({'message': 'User already exists'})

    users_collection.create_index("expirationDate", expireAfterSeconds=0)

    # The document will be automatically deleted after the expiration date has passed.
    expiration_date = datetime.datetime.utcnow() + timedelta(seconds=120)  # Set the expiration date to one hour from now
    # Hash the password using bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode(os.getenv("DECODE_ALGORITHM"))
    user_data = {'email': email, 'password': hashed_password, 'role': role, "expirationDate": expiration_date}

    # Store the user in the database
    users_collection.insert_one(user_data)

    # Set an HTTPOnly cookie with the user's email
    response = make_response(redirect(url_for('resend_2fa', email=email)))
    response.set_cookie('email', str(email), httponly=True)  # Set an HTTPOnly cookie

    return response

@login.route('/login', methods=['POST'])
def signin():
    if request.method == 'POST':
        data = request.get_json()  # Parse the request body as JSON
        email = data.get('email')  # Access 'new_password' from the JSON data
        password = data.get('password')
        user = users_collection.find_one({'email': email})
        
        if user:
            # Verify the password using check_password_hash
            if user["password"] != "":
                if bcrypt.check_password_hash(user['password'], password):
                    # The password is verified
                    totp = pyotp.TOTP(TOTP_SECRET)
                    token = totp.now()
                    store_totp[email] = token
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
                    
                    expiration_time = int(time.time()) + 3600  # 1 hour from now
                    user_info = {
                        "email": email,
                        "exp": expiration_time,
                        "role": user.get("role")
                    }
                    jwt_token = jwt.encode(user_info, JWT_SECRET_KEY, algorithm=os.getenv("HASH"))
                    jwt_token_str = jwt_token.decode("utf-8")

                    # Set the JWT token as an HTTPOnly cookie
                    response = make_response(redirect('/home'))
                    response.set_cookie('session', jwt_token_str, expires=datetime.utcnow() + timedelta(hours=1))
                    resp = {'token': jwt_token_str}
                    return resp
            else:
                return 'need to go to signup', 404
        else:
            return 'Please check your email and or password', 400

@login.route('/resend_2fa/<email>', methods=['POST'])
def resend_2fa(email):
    if request.method == 'POST':
        try:
            # Generate a new TOTP token for this request
            totp = pyotp.TOTP(TOTP_SECRET)
            new_token = totp.now()
            store_totp[email] = new_token
            message = Mail(
                from_email='dev.pixera@gmail.com',
                to_emails=[email],
                subject='Two-Factor Authentication',
                plain_text_content=f'Your new token is: {new_token}'
            )
            
            sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
            response = sg.send(message)
            
            return "Email sent", 200
        except Exception as e:
            return f"Email not sent. Error: {str(e)}", 500
    else:
        return "GET request is not allowed", 400

@login.route('/verify_2fa/<email>', methods=['POST'])
def verify_2fa(email):
    if request.method == 'POST':
        data = request.get_json()  # Parse the request body as JSON
        totp_token = data.get('totp_token')
        if (totp_token == store_totp[email]):
            flash('2FA verification successful! You are now logged in.')
            del store_totp[email]
            response_data = {'message': 'Success'}
            return jsonify(response_data), 200
        else:
            flash('2FA verification failed. Please check the TOTP token.')
            return "failed", 400
    response_data = {'message': 'bruh'}
    return jsonify(response_data), 200

@login.route('/verify_2fa_signup/<email>', methods=['POST'])
def verify_2fa_signup(email):
    if request.method == 'POST':
        data = request.get_json()  # Parse the request body as JSON
        totp_token = data.get('totp_token')
        totp = pyotp.TOTP(TOTP_SECRET)
        if totp.verify(totp_token):
            flash('2FA verification successful! You are now logged in.')
            users_collection.update_one({'email': email}, {'$unset': {'expirationDate': 1}})
            response_data = {'message': 'Success'}
            return jsonify(response_data), 200
        else:
            flash('2FA verification failed. Please check the TOTP token.')
            return "failed", 400
    response_data = {'message': 'bruh'}
    return jsonify(response_data), 200

@login.route('/forgot_password', methods=['POST'])
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
            except Exception:
                flash('An error occurred while sending the password reset link.')
        else:
            return 'not found', 404
    return 'success', 200

@login.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    if token in reset_tokens:
        email = reset_tokens[token]
        data = request.get_json()
        new_password = data.get('new_password')
        if not new_password:
            response_data = {'message': 'New password is required'}
            return jsonify(response_data), 400

        # Hash the new password
        hashed_password = bcrypt.generate_password_hash(new_password).decode(os.getenv("DECODE_ALGORITHM"))

        # Update the user's password in the database
        users_collection.update_one({'email': email}, {'$set': {'password': hashed_password}})

        del reset_tokens[token]
        response_data = {'message': 'Password reset successfully.'}
        return jsonify(response_data), 200
    else:
        response_data = {'message': 'Invalid or expired token'}
        return jsonify(response_data), 400

@login.route("/login_user")
def login_user():
    authorization_url, state = flow.authorization_url()
    print(authorization_url)
    return redirect(authorization_url)

@login.route("/callback")
def callback():
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
            "password": "",
            "role": ""  # You can set a default role for new users if needed
        }
        users_collection.insert_one(user_data)

    # Create a JWT token and include claims, including "exp" for expiration and "role" for the user's role
    expiration_time = int(time.time()) + 3600  # 1 hour from now
    user_info = {
        "google_id": id_info.get("sub"),
        "exp": expiration_time,
        "role": existing_user.get("role", "")  # Get the user's role or use a default if not present
    }
    jwt_token = jwt.encode(user_info, JWT_SECRET_KEY, algorithm=os.getenv("HASH"))
    jwt_token_str = jwt_token.decode("utf-8")

    # Set the JWT token as an HTTPOnly cookie
    response = make_response(redirect('/home'))
    response.set_cookie('session', jwt_token_str, expires=datetime.utcnow() + timedelta(hours=1))

    return response

@login.route("/logout")
def logout():
    response = make_response(redirect('/'))
    response.delete_cookie('session')
    return response

@login.route("/verify_token", methods=["POST"])  # Use POST method to send the JWT token in the request body
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