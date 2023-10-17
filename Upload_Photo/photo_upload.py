import os
from flask import Flask, request, render_template
from google.cloud import storage

app = Flask(__name__)

# Configure the Google Cloud Storage client
client = storage.Client.from_service_account_json("PixEra_GCP.json")
bucket = client.get_bucket("your-bucket-name")

@app.route('/upload_photo_to_GCP', methods=['GET', 'POST'])
def upload_photo_to_GCP():
    if request.method == 'POST':
        # Get form data
        title = request.form['title']
        description = request.form['description']
        tags = request.form['tags']
        file = request.files['file']

        if file:
            # Create a unique filename
            filename = os.path.join('uploads', file.filename)
            blob = bucket.blob(filename)

            # Upload the file to Google Cloud Storage
            blob.upload_from_string(file.read(), content_type=file.content_type)

            # Store metadata (title, description, tags) as metadata on the GCS object
            blob.metadata = {
                'title': title,
                'description': description,
                'tags': tags
            }
            blob.patch()

            return "File uploaded successfully!"
    
    return render_template('upload_form.html')

if __name__ == '__main__':
    app.run(debug=True)
