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
space_name = 'PixEra'

S3_ENDPOINT = "nyc3.digitaloceanspaces.com"
S3_BUCKET = "pixera"
S3_REGION = "nyc3"

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

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
    tags_list = json.loads(tags)
    
    if not access_key or not secret_key:
        return "AWS credentials not available", 401

    if not title:
        return "Please enter a title", 403

    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            key = f'{username}/Photos/{filename}'
    
            metadata = {
                'description': description,
                'tags': tags
            }

            # Get the file extension
            file_extension = filename.rsplit('.', 1)[1].lower()

            s3.upload_fileobj(
                file,
                S3_BUCKET,
                key,
                ExtraArgs={
                    'Metadata': metadata,
                    'ContentType': f'image/{file_extension}',  # Set content type based on the file extension
                    'ACL': 'public-read',  # Set image permission to "public"
                }
            )
            
            # Initialize likes and dislikes for the new photo
            photo_likes_dislikes[title] = {'likes': 0, 'dislikes': 0}
            # Store the image key in MongoDB
            mongo_collection.insert_one({'username': username, 'title': title, 'key': filename, 'likes_dislikes': photo_likes_dislikes[title],'tags':tags_list, 'description': description})

            return "File uploaded successfully", 200
        except NoCredentialsError:
            return "Upload failed due to invalid credentials", 500
    else:
        return "Invalid file type", 400
    
@photo_upload.route('/search', methods=['POST'])
def search_by_tags():
    data = request.form.to_dict()
    tag = data.get('tags')
    tags = json.loads(tag)
    try:
        matching_photos = mongo_collection.find({"tags": {"$in": tags}})

        image_info_list = []
        for photo in matching_photos:
            username = photo['username']  # Retrieve username
            photo_key = photo['key']  # Retrieve photo key

            # Construct the URL for the image
            base_url = f'https://pixera.nyc3.cdn.digitaloceanspaces.com/pixera/{username}/Photos/'
            image_url = f'{base_url}{photo_key}'

            image_info = {
                'url': image_url,
                'filename': photo_key,
                'username':username
            }
            image_info_list.append(image_info)

        return jsonify(image_info_list), 200
    except Exception as e:
        return {'message': str(e)}, 500

@photo_upload.route('/all_photographers', methods=['POST'])
def list_photographers():
    try:
        data = request.get_json()
        role = data.get('role')
        
        # Retrieve all photographers with the specified role
        photographers = mongo_user_collection.find({'role': role})
                
        photographer_data = {}

        # Iterate through each photographer and retrieve their image keys
        for photographer in photographers:
            username = photographer['username']
            user_keys = [entry['key'] for entry in mongo_collection.find({'username': username})]

            # Construct full URLs for each image using the keys
            base_url = f'https://pixera.nyc3.cdn.digitaloceanspaces.com/pixera/{username}/Photos/'
            photos = [{'url': f'{base_url}{key}', 'filename': key, 'username': username} for key in user_keys]

            # Store the photos in the dictionary with the photographer's username as the key
            photographer_data[username] = {'photos': photos}
                        
        return jsonify(photographer_data), 200

    except Exception as e:
        return {'message': str(e)}, 500

@photo_upload.route('/photo_upload/list', methods=['POST'])
def get_file_list():
    try:
        data = request.get_json()
        username = data.get('username')

        # Retrieve keys from MongoDB for the specified user
        user_keys = [entry['key'] for entry in mongo_collection.find({'username': username})]

        # Construct full URLs for each image using the keys
        base_url = f'https://pixera.nyc3.cdn.digitaloceanspaces.com/pixera/{username}/Photos/'
        image_info_list = [{'url': f'{base_url}{key}', 'filename': key} for key in user_keys]

        return jsonify(image_info_list), 200

    except Exception as e:
        return {'message': str(e)}, 500
    
@photo_upload.route('/uploadProfileImage', methods=['POST'])
def upload_profile_image():
    try:
        data = request.form.to_dict()
        username = data.get('username')

        if 'file' not in request.files:
            return "No file part", 402

        file = request.files['file']

        if file.filename == '':
            return "No selected file", 403

        if not access_key or not secret_key:
            return "AWS credentials not available", 401

        if file and allowed_file(file.filename):
            try:
                filename = secure_filename(file.filename)
                key = f'{username}/ProfileImage/{filename}'

                # Get the file extension
                file_extension = filename.rsplit('.', 1)[1].lower()

                s3.upload_fileobj(
                    file,
                    S3_BUCKET,
                    key,
                    ExtraArgs={
                        'ContentType': f'image/{file_extension}',  # Set content type based on the file extension
                        'ACL': 'public-read',  # Set image permission to "public"
                    }
                )
                
                if mongo_profile_collection.find_one({'username': username}) is None:
                    mongo_profile_collection.insert_one({'username': username, 'prof_key': key})
                else:
                    mongo_profile_collection.update_one({'username': username}, {'$set': {'prof_key': key}})

                base_url = f'https://pixera.nyc3.cdn.digitaloceanspaces.com/pixera/{username}/ProfileImage/{filename}'

                return jsonify(base_url), 200
            except NoCredentialsError:
                return "Upload failed due to invalid credentials", 500
        else:
            return "Invalid file type", 400

    except Exception as e:
        return {'message': str(e)}, 500
    
@photo_upload.route('/profile_image', methods=['POST'])
def profileImage():
    try:
        data = request.get_json()
        username = data.get('username')
        base_url = f'https://pixera.nyc3.cdn.digitaloceanspaces.com/pixera/'
        user_keys = [entry['prof_key'] for entry in mongo_profile_collection.find({'username': username})]
        image_urls = [f'{base_url}{key}' for key in user_keys]
        
        return jsonify(image_urls), 200
    except Exception as e:
        return {'message': str(e)}, 500
    
@photo_upload.route('/saveEditedData', methods=['POST'])
def save_edited_data():
    try:
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
        username = request.get_json().get('username')
        edited_data = request.get_json().get('editedData')

        # Update the user's data in MongoDB
        mongo_user_collection.update_one({'username': username}, {'$set': edited_data})
                        
        user_token = {
            'firstName': decoded_token['firstName'],
            'lastName': decoded_token['lastName'],
            'username': edited_data['username'],
            'email': decoded_token['email'],
            'country': decoded_token['country'],
            'city': decoded_token['city'],
            'role': decoded_token['role'],
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
    
@photo_upload.route('/fetchUserData/<username>', methods=['GET'])
def fetch_user_data(username):
    try:
        user_data = mongo_user_collection.find_one({'username': username})
        if user_data:
            user_info = {
                'description': user_data.get('description', ''),
                'twitterLink': user_data.get('twitterLink', ''),
                'instaLink': user_data.get('instaLink', ''),
                'linkedInLink': user_data.get('linkedInLink', ''),
                'username': user_data.get('username', '')
            }
            return jsonify(user_info), 200
        else:
            return "User not found", 404
    except Exception as e:
        return {'message': str(e)}, 500
    
@photo_upload.route('/like_dislike_count/<title>', methods=['POST'])
def get_like_dislike_count(title):
    try:
        data = request.get_json()
        username = data.get('name')
        
        user_likes_dislikes = mongo_collection.find_one({'username': username, 'key': title})
        
        if user_likes_dislikes:
            likes = user_likes_dislikes.get('likes_dislikes', {}).get('likes', 0)
            dislikes = user_likes_dislikes.get('likes_dislikes', {}).get('dislikes', 0)
            return jsonify({'likes': likes, 'dislikes': dislikes}), 200
        else:
            return "Photo not found for the user", 404
    except NoCredentialsError:
        return "Credentials not available", 403
    
@photo_upload.route('/fetch_image', methods=['POST'])
def fetch_image():
    try:
        data = request.form.to_dict()
        username = data.get('username')
        base_url = f'https://pixera.nyc3.cdn.digitaloceanspaces.com/pixera/{username}/Photos/'
        key = data.get('key')
        image_url = f'{base_url}{key}'

        image = mongo_collection.find_one({'username': username, 'key': key})

        response_data = {
            'image_url': image_url,
            'title': image['title'],
        }

        # Check if 'tags' and 'description' exist before adding to the response
        if 'tags' in image:
            response_data['tags'] = image['tags']

        if 'description' in image:
            response_data['description'] = image['description']

        return jsonify(response_data), 200
    except Exception as e:
        return {'message': str(e)}, 500


@photo_upload.route('/like/<title>', methods=['POST'])
def like_photo(title):
    try:
        data = request.get_json()
        username = data.get('name')

        # Find the user in the MongoDB collection
        user = mongo_collection.find_one({'username': username, 'key': title})

        if user:
            # Access the 'likes_dislikes' object from MongoDB for the specified title
            likes_dislikes = user.get('likes_dislikes', {})

            # Check if the user has already disliked
            dislikes_count = likes_dislikes.get('dislikes', 0)
            if dislikes_count > 0:
                # Decrement dislikes by 1
                dislikes_count -= 1
                # Update the 'likes_dislikes' object in MongoDB for the specified title
                mongo_collection.update_one(
                    {'username': username, 'key': title},
                    {'$set': {f'likes_dislikes.dislikes': dislikes_count}}
                )

            # Access the likes count for the specified title and increment it
            likes_count = likes_dislikes.get('likes', 0) + 1

            # Update the 'likes_dislikes' object in MongoDB for the specified title
            mongo_collection.update_one(
                {'username': username, 'key': title},
                {'$set': {f'likes_dislikes.likes': likes_count}}
            )

            return jsonify({'likes': likes_count}), 200
        else:
            return "User or Photo not found", 404
    except NoCredentialsError:
        return "Credentials not available", 404

@photo_upload.route('/dislike/<title>', methods=['POST'])
def dislike_photo(title):
    try:
        data = request.get_json()
        username = data.get('name')

        # Find the user in the MongoDB collection
        user = mongo_collection.find_one({'username': username, 'key': title})

        if user:
            # Access the 'likes_dislikes' object from MongoDB for the specified title
            likes_dislikes = user.get('likes_dislikes', {})

            # Check if the user has already liked
            likes_count = likes_dislikes.get('likes', 0)
            if likes_count > 0:
                # Decrement likes by 1
                likes_count -= 1
                # Update the 'likes_dislikes' object in MongoDB for the specified title
                mongo_collection.update_one(
                    {'username': username, 'key': title},
                    {'$set': {f'likes_dislikes.likes': likes_count}}
                )

            # Access the dislikes count for the specified title and increment it
            dislikes_count = likes_dislikes.get('dislikes', 0) + 1

            # Update the 'likes_dislikes' object in MongoDB for the specified title
            mongo_collection.update_one(
                {'username': username, 'key': title},
                {'$set': {f'likes_dislikes.dislikes': dislikes_count}}
            )

            return jsonify({'dislikes': dislikes_count}), 200
        else:
            return "User or Photo not found", 404
    except NoCredentialsError:
        return "Credentials not available", 404
    
@photo_upload.route('/delete/<title>', methods=['POST'])
def delete_photo(title):
    try:
        data = request.get_json()
        username = data.get('name')

        # Find the user in the MongoDB collection
        user = mongo_collection.find_one({'username': username, 'key': title})

        if user:
            # Delete the image from DigitalOcean Spaces
            filename = user.get('key')
            key = f'{username}/Photos/{filename}'
            s3.delete_object(Bucket=S3_BUCKET, Key=key)

            # Delete the image entry from MongoDB
            mongo_collection.delete_one({'username': username, 'key': title})

            return "Image deleted successfully", 200
        else:
            return "User or Photo not found", 404
    except NoCredentialsError:
        return "Credentials not available", 404

@photo_upload.route('/deleteAccount', methods=['DELETE'])
def delete_account():
    try:
        data = request.get_json()
        username = data.get('username')
        
        # Find the user in the MongoDB collection
        user = mongo_collection.find_one({'username': username, 'key': title})

        if user:
            # Query MongoDB to retrieve keys based on the username
            image_data = mongo_collection.find({'username': username_to_search})
            
            for image in image_data:
                filename = image["key"]
                # Delete all images from DigitalOcean Spaces Photos folder
                subpath = "Photos"
                key = f'{username}/{subpath}/{filename}'
                s3.delete_object(Bucket=S3_BUCKET, Key=key)

                # Delete all images from DigitalOcean Spaces ProfileImage folder
                subpath = "ProfileImage"
                key = f'{username}/{subpath}/{filename}'
                s3.delete_object(Bucket=S3_BUCKET, Key=key)

            return "Images deleted successfully", 200
        else:
            return "User or Photo not found", 404


        # Remove the user from the database
        result = mongo_user_collection.delete_one({'username': username})

        if result.deleted_count > 0:
            response_data = {'message': 'Account deleted successfully'}
            return jsonify(response_data), 200
        else:
            response_data = {'message': 'User not found'}
            return jsonify(response_data), 404

    except Exception as e:
        response_data = {'message': str(e)}
        return jsonify(response_data), 500
