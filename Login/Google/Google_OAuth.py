import os
import pathlib
import requests
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

app = Flask("Google Login App")
app.secret_key = "CodeSpecialist.com"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost:3000/callback"
)

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper

@app.route("/login") ##router login displays the login page
def login():
    authorization_url, state = flow.authorization_url() ##checks if the states match
    session["state"] = state
    return redirect(authorization_url)

def validate(auth_token): ##revalid token if time is off
    try:
        idinfo = id_token.verify_oauth2_token(
            auth_token, requests.Request(), clock_skew_in_seconds=100) ##token skew to offset token response time

        if 'accounts.google.com' in idinfo['iss']:
            return idinfo

    except:
        return "The token is either invalid or has expired"

@app.route("/callback") ##validates token and redirects to Google
def callback():
    validate(flow.fetch_token(authorization_response=request.url))

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token( ##receive user info and store
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub") ##use sessions to display and store user info
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    return redirect("/protected_area")

@app.route("/logout") ##logout
def logout():
    session.clear()
    return redirect("/")

@app.route("/") ##login page when app first starts
def index():
    return "Welcome to PixEra <a href='/login'><button>Login</button></a>"

@app.route("/protected_area") ##should be landing page
@login_is_required
def protected_area():
    return f"Hello {session['name']}! Hello {session['email']}! <br/> <a href='/logout'><button>Logout</button></a>"

if __name__ == "__main__":
    app.run(debug=True, host = "localhost", port = 3000)