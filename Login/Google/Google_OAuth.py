import os
import pathlib
import requests
import json
from flask import Flask, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import concurrent.futures
import jwt
import time

app = Flask("Google Login App")
app.secret_key = os.getenv("APP_SECRET_KEY")

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost:5000/callback"
)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

def login_is_required(function):
    def wrapper(*args, **kwargs):
        token = request.json()

        if not token:
            return abort(401)  # Authorization required

        try:
            decoded_token = jwt.decode(token, JWT_SECRET_KEY, algorithms=[os.getenv("HASH")])
            if "google_id" not in decoded_token:
                return abort(401)
        except jwt.ExpiredSignatureError:
            return abort(401)  # Token has expired

        return function()

    return wrapper

@app.route("/login")
def login():
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

    with concurrent.futures.ThreadPoolExecutor() as executor:
        id_info = executor.submit(validate_and_get_id_info).result()

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
    return "Welcome to PixEra <a href='/login'><button>Login</button></a>"

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


if __name__ == "__main__":
    app.run(debug=True, host="localhost", port=5000)
