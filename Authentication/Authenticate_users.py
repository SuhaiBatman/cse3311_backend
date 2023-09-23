import requests

backend_endpoint_url = 'http://localhost:3000/authenticate'

username = 'user'
password = 'password'

credentials = {
    'username': username,
    'password': password
}

# Send a POST request to the backend endpoint to authenticate the user
try:
    response = requests.post(backend_endpoint_url, json=credentials)

    if response.status_code == 200:
        print('User authentication successful!')
    elif response.status_code == 401:
        print('Authentication failed. Invalid username or password.')
    else:
        print(f'Error: {response.status_code}')
except requests.exceptions.RequestException as e:
    print(f'Error: {e}')