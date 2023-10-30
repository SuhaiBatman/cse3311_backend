import requests
import os
import boto3
import botocore.session
from botocore.exceptions import NoCredentialsError
from flask import Flask, request, render_template, send_from_directory, url_for

app = Flask(__name__)

# Specify Digital Ocean Spaces settings
S3_ENDPOINT = 'nyc3.digitaloceanspaces.com'
S3_BUCKET = 'pixera'
S3_ACCESS_KEY = 'your_access_key'
S3_SECRET_KEY = 'your_secret_key'
S3_REGION = 'nyc3'

# Construct the URL for listing the contents of the bucket
url = f'https://{S3_BUCKET}.{S3_REGION}.digitaloceanspaces.com/'

# Configure S3 connection 
s3 = boto3.client('s3', endpoint_url=f'https://{S3_BUCKET}.{S3_ENDPOINT}', aws_access_key_id=S3_ACCESS_KEY, aws_secret_access_key=S3_SECRET_KEY)

# Configure a Client
# https://docs.digitalocean.com/products/spaces/reference/s3-sdk-examples/
session = boto3.session.Session()
# Configures to use subdomain/virtual calling format.
# *** we should replace with os.getenv() ***
client = session.client('s3',
                        config=botocore.config.Config(s3={'addressing_style': 'virtual'}), 
                        region_name='nyc3',
                        endpoint_url='https://nyc3.digitaloceanspaces.com',
                        aws_access_key_id=S3_ACCESS_KEY,
                        aws_secret_access_key=S3_SECRET_KEY)

# Specify the folder where uploaded photos will be stored
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create a list to store uploaded file names
uploaded_files = []

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part"

    file = request.files['file']

    if file.filename == '':
        return "No selected file"

    if file:
        try:
            # Generate a unique key (filename) for the object in Spaces
            key = file.filename
            s3.upload_fileobj(file, S3_BUCKET, key)
            
            # Append the uploaded file name to the list
            uploaded_files.append(key)
            
            return render_template('upload_success.html')
        except NoCredentialsError:
            return '''
            "Credentials not available"
            <form method="GET" action="/">
                <input type="submit" value="Back to Main Page">
            </form>
            '''

@app.route('/download/pixera/pixera/<filename>')
def download_file(filename):
    try:
        # Download the file from Digital Ocean Spaces
        s3.download_file(S3_BUCKET, filename, filename)
        
        # Send the downloaded file as a response
        return send_from_directory(".", filename)
    except NoCredentialsError:
        return '''
            "Credentials not available"
            <form method="GET" action="/">
                <input type="submit" value="Back to Main Page">
            </form>
            '''

@app.route('/list')
def list_files():
    response = client.list_objects(Bucket=S3_BUCKET)
    # Clear uploaded_files list
    uploaded_files.clear()
    for obj in response['Contents']:
        print(obj['Key'])
        uploaded_files.append(obj['Key'])
    

    return render_template('list.html', files=uploaded_files, url=url)


if __name__ == '__main__':
    app.run(debug=True)
