from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth
from dotenv import load_dotenv, dotenv_values

import os
import requests

load_dotenv()

app = Flask(__name__)

app.secret_key = 'cse-3311-secret-key'

oauth = OAuth(app)

#Google connection
google = oauth.remote_app(
    'google',
    consumer_key = os.getenv("CLIENT_ID"), #Given by cloud
    consumer_secret= os.getenv("CLIENT_SECRET"), #Given by cloud
    request_token_params = {
        'scope': 'email',  # might need user info too
    },
    base_url = 'https://www.googleapis.com/oauth2/v1/',
    request_token_url = None,
    access_token_method = 'POST',
    access_token_url = 'https://accounts.google.com/o/oauth2/token',
    authorize_url = 'https://accounts.google.com/o/oauth2/auth',
)

#router for connection
@app.route('/')
def index():
    if 'google_token' in session:
        user_info = get_google_user_info()
        return f'Logged in as: {user_info["email"]}'
    return 'Not logged in. <a href="/login">Login with Google</a>'

#Authorize login
@app.route('/login')
def login():
    return google.authorize(callback=url_for('authorized', _external=True))

#logout
@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))

#successful login
@app.route('/login/authorized')
def authorized():
    resp = google.authorized_response()

    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )

    session['google_token'] = (resp['access_token'], '')
    user_info = get_google_user_info()
    return f'Successfully logged in as {user_info["email"]}'

#retrieve token from Google
@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

#get user info
def get_google_user_info():
    headers = {'Authorization': f'Bearer {get_google_oauth_token()[0]}'}
    response = requests.get('https://www.googleapis.com/oauth2/v1/userinfo', headers=headers)
    return response.json()


if __name__ == '__main__':
    app.run(debug=True)
