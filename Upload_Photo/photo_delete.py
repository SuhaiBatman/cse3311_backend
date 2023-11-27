from flask import Flask, request, Blueprint, jsonify, make_response
from werkzeug.utils import secure_filename
from botocore.exceptions import NoCredentialsError
import os
import boto3
from dotenv import load_dotenv
import json
from pymongo import MongoClient
import jwt

load_dotenv()

photo_upload = Blueprint("photo_upload", __name__)

# Initialize MongoDB client
mongo_client = MongoClient(os.getenv("MONGO_URL"))
mongo_db = mongo_client['PixEraDB']
mongo_collection = mongo_db['image_keys']
mongo_profile_collection = mongo_db['profile_keys']
mongo_user_collection = mongo_db['Users']

access_key = os.getenv("DO_ACCESS_KEY")
secret_key = os.getenv("DO_SECRET_KEY")

S3_ENDPOINT = "nyc3.digitaloceanspaces.com"
S3_BUCKET = "pixera"
S3_REGION = "nyc3"

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

s3 = boto3.client('s3', endpoint_url=f'https://{S3_BUCKET}.{S3_ENDPOINT}', aws_access_key_id=access_key, aws_secret_access_key=secret_key)
s3_list = boto3.client('s3', endpoint_url=f'https://{S3_BUCKET}.{S3_ENDPOINT}')

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'mov', 'mp4'}

app = Flask(__name__)


def delete_photo_advanced(file_key):
    try:
        # Delete the file
        response = s3.delete_object(
            Bucket=S3_BUCKET,
            Key=file_key
        )
        
        if response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 204:
            print(f"File {file_key} deleted successfully.")
        else:
            print(f"Failed to delete file. Response: {response}")
    except Exception as e:
        print(f"Error deleting file: {e}")

def delete_photo(path):
    try:
        # Delete the file
        s3.delete_object(
            Bucket=S3_BUCKET,
            Key=path
        )
        print(f"File {path} deleted successfully.")
    except Exception as e:
        print(f"Error deleting file: {e}")


def play_bucket():
    # Create a new Space.
    #s3.create_bucket(Bucket='dasani')

    response = s3_list.list_objects_v2(Bucket='pixera')
    print(response)
    # for obj in response['Contents']:
    #     print(obj['Key'])



username = "diegovester"
title = "Cat_sticker.png"
path=f'{username}/Photos/{title}'

play_bucket()