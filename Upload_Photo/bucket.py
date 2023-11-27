import boto3
from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()
# Set your Digital Ocean Space credentials
access_key = 'DO009AZG6QQGYQE77YDN'
secret_key = 'HDWc8Tlpkcp+keYk97Tf0JNi+aeIQoNGn8hvRdBMq9Q'
S3_BUCKET = 'pixera'

# Create an S3 client
s3 = boto3.client('s3', endpoint_url="https://pixera.nyc3.digitaloceanspaces.com",
                  aws_access_key_id=access_key, aws_secret_access_key=secret_key)


# Initialize MongoDB client
mongo_client = MongoClient(os.getenv("MONGO_URL"))
mongo_db = mongo_client['PixEraDB']
mongo_collection = mongo_db['image_keys']
mongo_profile_collection = mongo_db['profile_keys']
mongo_user_collection = mongo_db['Users']



# Specify the username
username = "diegovester"
filename = "WIN.jpg"
# Find the user in the MongoDB collection

# user = mongo_collection.find_one({'username': username, 'key': title})
# print(user)

# if user:
#     print("yes")
# else:
#     print("nope")
key = f'{username}/Photos/{filename}'
response = s3.delete_object(Bucket=S3_BUCKET, Key=key)
print(response["ResponseMetadata"])

# Query MongoDB to retrieve keys based on the username
# image_data = mongo_collection.find({'username': username_to_search})
# print(image_data)

# for image in image_data:
#     key = image["key"]
#     print(key)



# for image in image_data:
#     key_list = list(image.keys())
#     print(f"Keys for {username_to_search}:{key_list}")
# else:
#     print(f"User {username_to_search} not found.")


# if image_data:
#     keys_list = list(image_data.keys())
#     print(f"Keys for {username_to_search}:{keys_list}")
# else:
#     print(f"User {username_to_search} not found.")