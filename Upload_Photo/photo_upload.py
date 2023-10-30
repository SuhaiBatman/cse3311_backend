import boto3
from botocore.exceptions import NoCredentialsError

# DigitalOcean Spaces credentials
access_key = 'your_access_key'
secret_key = 'your_secret_key'
space_name = 'your_space_name'

# Upload a file to DigitalOcean Spaces
def upload_file_to_do_spaces(file_path, key):
    try:
        s3 = boto3.client('s3',
            endpoint_url='https://your-space-name.nyc3.digitaloceanspaces.com',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )

        s3.upload_file(file_path, space_name, key)
        return True
    except NoCredentialsError:
        print("No AWS credentials found")
        return False

if __name__ == "__main__":
    file_path = 'path_to_your_photo.jpg'  # Replace with the actual path of your photo
    key = 'uploads/photo.jpg'  # The key under which the file will be stored in DigitalOcean Spaces

    success = upload_file_to_do_spaces(file_path, key)
    if success:
        print(f"File {file_path} uploaded successfully to DigitalOcean Spaces.")
    else:
        print("File upload failed.")
