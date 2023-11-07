import os
import boto3
from botocore.exceptions import NoCredentialsError
from flask import Flask, request, Blueprint, jsonify  # Import jsonify to return JSON responses
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

photo_upload = Blueprint("photo_upload", __name__)

# Now you can access the variables
access_key = os.getenv("DO_ACCESS_KEY")
secret_key = os.getenv("DO_SECRET_KEY")
space_name = 'PixEra'

# Specify Digital Ocean Spaces settings
S3_ENDPOINT = "nyc3.digitaloceanspaces.com"
S3_BUCKET = "pixera"
S3_REGION = "nyc3"

# Configure S3 connection
s3 = boto3.client('s3', endpoint_url=f'https://{S3_BUCKET}.{S3_ENDPOINT}', aws_access_key_id=access_key, aws_secret_access_key=secret_key)

# Create a separate S3 client for listing objects
s3_list = boto3.client('s3', endpoint_url=f'https://{S3_BUCKET}.{S3_ENDPOINT}')

# Define the allowed file extensions and a function to check if the file extension is allowed
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'mov', 'mp4'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@photo_upload.route('/upload/<email>', methods=['POST'])
def upload_file(email):
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "No selected file", 400

    title = request.form.get('title')  # Get the title from the form data

    if not access_key or not secret_key:
        return "AWS credentials not available", 401

    if not title:
        return "Please enter a title", 403

    if file and allowed_file(file.filename):
        try:
            # Secure the filename to prevent directory traversal
            filename = secure_filename(file.filename)

            # Generate a unique key (filename) for the object in Spaces
            key = f'{email}/{filename}'  # get this to upload to email instead of uploads

            s3.upload_fileobj(file, S3_BUCKET, key)

            return "File uploaded successfully", 200
        except NoCredentialsError:
            return "Upload failed due to invalid credentials", 500
    else:
        return "Invalid file type", 400

@photo_upload.route('/list')
def list_files():
    try:
        response = s3_list.list_objects(Bucket=S3_BUCKET)
        # Extract the list of object keys
        object_keys = [obj['Key'] for obj in response.get('Contents', [])]
        return jsonify(object_keys), 200
    except NoCredentialsError:
        return "Credentials not available", 404

@photo_upload.route('/download/pixera/pixera/<filename>')
def download_file(filename):
    try:
        # Download the file from Digital Ocean Spaces
        s3.download_file(S3_BUCKET, filename, filename)
        return "File downloaded successfully", 200
    except NoCredentialsError:
        return "Credentials not available", 404
