from flask import Flask, request, jsonify
from flask_cors import CORS
import os

from Login.login import login
from Upload_Photo.photo_upload import photo_upload

app = Flask(__name__, static_url_path="", static_folder="../cse3311_frontend/build")
app.register_blueprint(login)
app.register_blueprint(photo_upload)
CORS(app)

@app.route('/')
@app.route('/home')
@app.route('/signup')
@app.route('/forgot_password')
@app.route('/reset_password/<token>')
@app.route('/google_oauth')
@app.route('/verify2FA')
@app.route('/profile')
@app.route('/photographer/<name>')
@app.route('/photographer/<name>/<photoid>')
@app.route('/user_profile')
@app.route('/request_booking')
@app.route('/proposal')

def index_file(**kwarg):
    return app.send_static_file('index.html')

if __name__ == "__main__":
    app.secret_key = os.getenv("SECRET_KEY")
    app.run(debug=True, host="localhost", port=3000)