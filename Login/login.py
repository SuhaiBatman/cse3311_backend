from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify
from flask_mail import Mail, Message
import random
import string
from pymongo import MongoClient
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import pyotp
from passlib.hash import pbkdf2_sha256
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
from dotenv import load_dotenv
from bson import ObjectId
import json
import uuid

load_dotenv()

login = Blueprint("login", __name__)

# Define your environment variables here
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
TOTP_SECRET = os.getenv("TOTP_SECRET")

mongo_client = MongoClient(os.getenv("MONGO_URL"))
db = mongo_client['PixEraDB']
users_collection = db['Users']
mongo_collection = db['image_keys']
date_collection = db['dates']

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
    data = request.get_json()
    firstName = data.get('firstName')
    lastName = data.get('lastName')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    country = data.get('country')
    city = data.get('city')
    role = data.get('role')
    photographertype = data.get('roleTags', [])  # Get tags or default to an empty list

    # Check if the user already exists
    user = users_collection.find_one({'email': email})

    if user:
        return {'message': 'User already exists'}, 202

    users_collection.create_index("expirationDate", expireAfterSeconds=3600)

    # The document will be automatically deleted after the expiration date has passed.
    expiration_time = int(time.time()) + 3600  # 1 hour from now
    # Hash the password using pbkdf2_sha256
    hashed_password = pbkdf2_sha256.using(rounds=1000).hash(password)

    user_data = {
        'firstName': firstName,
        'lastName': lastName,
        'username': username,
        'email': email,
        'password': hashed_password,
        'country': country,
        'city': city,
        'role': role,
        'description': 'Tell us about yourself!',
        'twitterLink': 'https://twitter.com/',
        'instaLink': 'https://www.instagram.com/',
        'linkedInLink': 'https://www.linkedin.com/',
        'photographertype': photographertype,
        'expirationDate': expiration_time
    }

    username_exists = users_collection.find_one({'username': username})

    if username_exists:
        return "username already exists, please try again", 400
    else:
        # Store the user in the database
        result = users_collection.insert_one(user_data)

    # Convert the ObjectId to its string representation
    user_data['_id'] = str(result.inserted_id)
    
    user_token = {
        'firstName': firstName,
        'lastName': lastName,
        'username': username,
        'email': email,
        'country': country,
        'city': city,
        'role': role,
        'photographertype': photographertype,
        'exp': expiration_time
    }

    jwt_token = jwt.encode(user_token, JWT_SECRET_KEY, algorithm=os.getenv("HASH"))
    jwt_token_str = jwt_token.decode("utf-8")

    if jwt_token_str:
        # Create a response with a custom header
        response = make_response({'message': 'Login successful'})
        response.headers['Authorization'] = f'Bearer {jwt_token_str}'
        return response, 200
    
@login.route('/searchByPhotographerTag', methods=['POST'])
def photographersearch():
    data = request.form.to_dict()
    tag = data.get('tags')
    tags = json.loads(tag)
    try:
        # Find matching photographers based on tags
        matching_photographers = users_collection.find({"photographertype": {"$in": tags}})
        # Extract usernames of matching photographers
        usernames = [photographer['username'] for photographer in matching_photographers]
        image_info_list = []
        for username in usernames:
            image_info={
                'username':username
            }
            image_info_list.append(image_info)

        return jsonify(image_info_list), 200
    except Exception as e:
        return {'message': str(e)}, 500

    
@login.route('/login', methods=['POST'])
def signin():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        hashed_password = pbkdf2_sha256.using(rounds=1000).hash(password)
        user = users_collection.find_one({'email': email})

        if user:
            if pbkdf2_sha256.verify(password, user['password']):
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
                    'firstName': user.get('firstName'),
                    'lastName': user.get('lastName'),
                    'username': user.get('username'),
                    'country': user.get('country'),
                    'city': user.get('city'),
                    "email": email,
                    "exp": expiration_time,
                    "photographertype": user.get('photographertype'),
                    "role": user.get("role")
                }
                jwt_token = jwt.encode(user_info, JWT_SECRET_KEY, algorithm=os.getenv("HASH"))
                jwt_token_str = jwt_token.decode("utf-8")

                if jwt_token_str:
                    # Create a response with a custom header
                    response = make_response({'message': 'Login successful'})
                    response.headers['Authorization'] = f'Bearer {jwt_token_str}'
                    return response, 200
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
        data = request.get_json()
        totp_token = data.get('totp_token')
        if (totp_token == store_totp[email]):
            flash('2FA verification successful! You are now logged in.')
            if(users_collection['expirationDate'] != None):
                users_collection.update_one({'email': email}, {'$unset': {'expirationDate': 1}})
            del store_totp[email]
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
        email = request.form.get('email')
        if email:
            user = users_collection.find_one({'email': email})
            if user:
                # Generate a random reset token
                token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))
                reset_tokens[token] = email
                
                # Send a reset email with a link using SendGrid
                reset_link = url_for('login.reset_password', token=token, _external=True)
                message = Mail(
                    from_email='dev.pixera@gmail.com',
                    to_emails=[email],
                    subject='Password Reset',
                    plain_text_content=f'To reset your password, click the following link: {reset_link}'
                )
                try:
                    sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
                    response = sg.send(message)
                    return 'Password reset link sent successfully', 200
                except Exception:
                    flash('An error occurred while sending the password reset link.')
                    return 'Failed', 403
            else:
                return 'User not found', 404
        else:
            return 'Invalid email', 400
    else:
        return 'Method not allowed', 405

@login.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    if token in reset_tokens:
        email = reset_tokens[token]
        data = request.get_json()
        new_password = data.get('new_password')
        if not new_password:
            response_data = {'message': 'New password is required'}
            return jsonify(response_data), 400

        # Hash the new password using pbkdf2_sha256
        hashed_password = pbkdf2_sha256.using(rounds=1000).hash(new_password)

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
            "role": "",  # You can set a default role for new users if needed
            'description': 'Tell us about yourself!',
            'twitterLink': 'https://twitter.com/',
            'instaLink': 'https://www.instagram.com/',
            'linkedInLink': 'https://www.linkedin.com/',
        }
        users_collection.insert_one(user_data)

        # Create a JWT token and include claims, including "exp" for expiration and "role" for the user's role
        expiration_time = int(time.time()) + 3600  # 1 hour from now
        user_info = {
            "google_id": id_info.get("sub"),
            "email": user_email,
            "exp": expiration_time,
        }
        jwt_token = jwt.encode(user_info, JWT_SECRET_KEY, algorithm=os.getenv("HASH"))
        jwt_token_str = jwt_token.decode("utf-8")

        response = make_response(redirect('/google_oauth'))
        response.set_cookie('token', jwt_token_str, expires=datetime.utcnow() + timedelta(hours=1))
        return response, 200
    elif existing_user:
        # Create a JWT token and include claims, including "exp" for expiration and "role" for the user's role
        expiration_time = int(time.time()) + 3600  # 1 hour from now
        user_info = {
            "google_id": id_info.get("sub"),
            'firstName': existing_user['firstName'],
            'lastName': existing_user['lastName'],
            'username': existing_user['username'],
            'country': existing_user['country'],
            'city': existing_user['city'],
            "email": user_email,
            "exp": expiration_time,
            "role": existing_user['role'],
            'description': existing_user['description'],
            'twitterLink': existing_user['twitterLink'],
            'instaLink': existing_user['instaLink'],
            'linkedInLink': existing_user['linkedInLink'],
        }
        jwt_token = jwt.encode(user_info, JWT_SECRET_KEY, algorithm=os.getenv("HASH"))
        jwt_token_str = jwt_token.decode("utf-8")

        response = make_response(redirect('/home'))
        response.set_cookie('token', jwt_token_str, expires=datetime.utcnow() + timedelta(hours=1))
        return response, 200

@login.route('/google_oauth', methods=['POST'])
def google_oauth():
    try:
        data = request.get_json()
        # Retrieve the token from the request headers
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Authorization token missing'}), 401

        # Remove the 'Bearer ' prefix from the token
        token = token.replace('Bearer ', '')

        # Decode and verify the token
        try:
            decoded_token = jwt.decode(token, JWT_SECRET_KEY, algorithms=[os.getenv("HASH")])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        # Extract user information from the decoded token
        email = decoded_token['email']
        username = data.get('username')
        user_data = {
            'firstName': data.get('firstName'),
            'lastName': data.get('lastName'),
            'username': username,
            'email': email,
            'country': data.get('country'),
            'city': data.get('city'),
            'role': data.get('role'),
            'photographertype': data.get('roleTags', [])
        }
        
        username_exists = users_collection.find_one({'username': username})

        if username_exists:
            return "username already exists, please try again", 400
        else:
            # Update the user's data in MongoDB
            users_collection.update_one({'email': email}, {'$set': user_data})
                        
        user_token = {
            'firstName': data.get('firstName'),
            'lastName': data.get('lastName'),
            'username': data.get('username'),
            'email': decoded_token['email'],
            'country': data.get('country'),
            'city': data.get('city'),
            'role': data.get('role'),
            'photographertype': data.get('roleTags'),
            'exp': decoded_token['exp']
        }
        
        # Encode a new token with updated user information
        jwt_token = jwt.encode(user_token, JWT_SECRET_KEY, algorithm=os.getenv("HASH"))
        jwt_token_str = jwt_token.decode("utf-8")

        response = make_response({'message': 'Login successful'})
        response.headers['Authorization'] = f'Bearer {jwt_token_str}'
        return response, 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    
@login.route('/request_booking', methods=['POST'])
def request_booking():
    if request.method == 'POST':
        token = request.headers.get('Authorization')
        token = token.replace('Bearer ', '')
        decoded_token = jwt.decode(token, JWT_SECRET_KEY, algorithms=[os.getenv("HASH")])
        email = decoded_token['email']
        
        data = request.get_json()
        name = data.get('name')
        quote = data.get('quote')
        
        if email:
            user = users_collection.find_one({'username': name})
            photographerEmail = user['email']
            
            if user:
                # Generate a unique ID for the quote
                quote_id = str(uuid.uuid4())

                # Save the quote and quote_ID to the MongoDB collection
                date_data = {
                    'quote_ID': quote_id,
                    'photographerUsername': name,
                    'clientEmail': decoded_token['email'],
                    'quote': quote
                }
                date_collection.insert_one(date_data)
                                
                # Include the quote_ID in the URL link
                request_link = url_for('login.proposal', quote_id=quote_id, _external=True)
                message = Mail(
                    from_email='dev.pixera@gmail.com',
                    to_emails=[photographerEmail],
                    subject='Booking Request',
                    plain_text_content=f'To add this booking to your calendar, click the following link: {request_link}'
                )
                
                try:
                    sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
                    response = sg.send(message)
                    return 'Link sent successfully', 200
                except Exception:
                    flash('An error occurred while sending the email.')
                    return 'Failed to send email', 403
            else:
                return 'User not found', 404
        else:
            return 'Invalid email', 400
    else:
        return 'Method not allowed', 405
    
@login.route('/proposal/<quote_id>', methods=['POST'])
def proposal(quote_id):
    if request.method == 'POST':
        quote = date_collection.find_one({'quote_ID': quote_id})
        
        if quote:
            # Convert ObjectId to string
            quote['_id'] = str(quote['_id'])
            return jsonify(quote)
        else:
            return 'Quote not found', 404
    else:
        return 'Method not allowed', 405
    
@login.route('/proposal/<quote_id>/accept', methods=['POST'])
def proposal_accept(quote_id):
    if request.method == 'POST':
        quote = date_collection.find_one({'quote_ID': quote_id})

        if quote:
            # Update the quote to mark it as accepted
            date_collection.update_one({'quote_ID': quote_id}, {'$set': {'accepted': True}})

            return 'Quote accepted successfully', 200
        else:
            return 'Quote not found', 404
    else:
        return 'Method not allowed', 405
    
@login.route('/get_quotes/<username>', methods=['GET'])
def get_quotes(username):
    # Fetch only accepted quotes for the given username
    quotes = date_collection.find({'photographerUsername': username, 'accepted': True})

    # Prepare the events array
    events = []
    for quote in quotes:
        # Access the 'type' attribute from the quote object
        quote_type = quote.get('quote', {}).get('type', '')
        actual_quote = quote.get('quote', {})

        events.append({
            'id': str(quote['_id']),
            'title': quote_type,
            'startDay': actual_quote['sDay'],
            'startTime': actual_quote['sTime'],
            'endDay': actual_quote['eDay'],
            'endTime': actual_quote['eTime'],
            'status': 'Accepted'
        })

    return jsonify(events), 200