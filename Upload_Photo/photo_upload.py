from flask import Flask, request, Blueprint, jsonify
from werkzeug.utils import secure_filename
from botocore.exceptions import NoCredentialsError
import os
import boto3
from dotenv import load_dotenv
import json
from pymongo import MongoClient

load_dotenv()

photo_upload = Blueprint("photo_upload", __name__)

# Initialize MongoDB client
mongo_client = MongoClient(os.getenv("MONGO_URL"))
mongo_db = mongo_client['PixEraDB']
mongo_collection = mongo_db['image_keys']

access_key = os.getenv("DO_ACCESS_KEY")
secret_key = os.getenv("DO_SECRET_KEY")
space_name = 'PixEra'

S3_ENDPOINT = "nyc3.digitaloceanspaces.com"
S3_BUCKET = "pixera"
S3_REGION = "nyc3"

s3 = boto3.client('s3', endpoint_url=f'https://{S3_BUCKET}.{S3_ENDPOINT}', aws_access_key_id=access_key, aws_secret_access_key=secret_key)
s3_list = boto3.client('s3', endpoint_url=f'https://{S3_BUCKET}.{S3_ENDPOINT}')

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'mov', 'mp4'}

# Dictionary to store likes and dislikes for each photo
photo_likes_dislikes = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@photo_upload.route('/upload', methods=['POST'])
def upload_file():
    data = request.form.to_dict()
    username = data.get('username')

    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "No selected file", 400

    title = data.get('title')
    
    description = data.get('description')
    tags = data.get('tags')
    
    if not access_key or not secret_key:
        return "AWS credentials not available", 401

    if not title:
        return "Please enter a title", 403

    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            key = f'{username}/{title}'
    
            metadata = {
                'description': description,
                'tags': tags
            }

            s3.upload_fileobj(
                file,
                S3_BUCKET,
                key,
                ExtraArgs={'Metadata': metadata}
            )
            
            # Store the image key in MongoDB
            mongo_collection.insert_one({'username': username, 'title': title, 'key': key})

            # Initialize likes and dislikes for the new photo
            photo_likes_dislikes[title] = {'likes': 0, 'dislikes': 0}

            return "File uploaded successfully", 200
        except NoCredentialsError:
            return "Upload failed due to invalid credentials", 500
    else:
        return "Invalid file type", 400

@photo_upload.route('/photo_upload/list', methods=['POST'])
def get_file_list():
    try:
        data = request.get_json()
        username = data.get('username')
        print(username)

        # Retrieve keys from MongoDB for the specified user
        user_keys = [entry['key'] for entry in mongo_collection.find({'username': username})]

        # Construct full URLs for each image using the keys
        base_url = f'https://cloud.digitalocean.com/spaces/pixera?path=pixera'
        image_urls = [f'{base_url}/{key}' for key in user_keys]
        print(image_urls)

        return jsonify(image_urls), 200

    except Exception as e:
        return {'message': str(e)}, 500
    
@photo_upload.route('/download/<filename>')
def download_file(filename):
    try:
        s3.download_file(S3_BUCKET, filename, filename)
        return "File downloaded successfully", 200
    except NoCredentialsError:
        return "Credentials not available", 404

@photo_upload.route('/like/<title>', methods=['POST'])
def like_photo(title):
    if title in photo_likes_dislikes:
        photo_likes_dislikes[title]['likes'] += 1
        return jsonify(photo_likes_dislikes[title]), 200
    else:
        return "Photo not found", 404

@photo_upload.route('/dislike/<title>', methods=['POST'])
def dislike_photo(title):
    if title in photo_likes_dislikes:
        photo_likes_dislikes[title]['dislikes'] += 1
        return jsonify(photo_likes_dislikes[title]), 200
    else:
        return "Photo not found", 404
