from urllib import request

import pytest

class TestLogin:
    # User enters valid email and password, receives TOTP token email, and is redirected to 2FA verification page
    def test_valid_email_and_password(self, mocker):
        # Mock the request form data
        mocker.patch.object(request, 'form', {'email': 'test@example.com', 'password': 'password'})
    
        # Mock the users_collection.find_one() method to return a user
        mocker.patch.object(users_collection, 'find_one', return_value={'email': 'test@example.com', 'password': 'password'})
    
        # Mock the SendGridAPIClient.send() method to return a successful response
        mocker.patch.object(SendGridAPIClient, 'send', return_value='success')
    
        # Call the login function
        response = login()
    
        # Assert that the user is redirected to the verify_2fa page
        assert response.location == url_for('verify_2fa', email='test@example.com')
    
        # Assert that the flash message is displayed
        assert 'A TOTP token has been sent to your email. Please check your email and enter the token.' in flask.session['_flashes']
    
        # Assert that the SendGridAPIClient.send() method is called with the correct arguments
        SendGridAPIClient.send.assert_called_once_with(mocker.ANY)
    
        # Assert that the users_collection.find_one() method is called with the correct arguments
        users_collection.find_one.assert_called_once_with({'email': 'test@example.com', 'password': 'password'})

    # User enters invalid email or password and receives error message
    def test_invalid_email_or_password(self, mocker):
        # Mock the request form data
        mocker.patch.object(request, 'form', {'email': 'test@example.com', 'password': 'password'})
    
        # Mock the users_collection.find_one() method to return None
        mocker.patch.object(users_collection, 'find_one', return_value=None)
    
        # Call the login function
        response = login()
    
        # Assert that the user is not redirected
        assert response.location is None
    
        # Assert that the flash message is displayed
        assert 'Login failed. Please check your email and password.' in flask.session['_flashes']
    
        # Assert that the users_collection.find_one() method is called with the correct arguments
        users_collection.find_one.assert_called_once_with({'email': 'test@example.com', 'password': 'password'})

    # User enters email that is not registered and receives error message
    def test_unregistered_email(self, mocker):
        # Mock the request form data
        mocker.patch.object(request, 'form', {'email': 'test@example.com', 'password': 'password'})
    
        # Mock the users_collection.find_one() method to return None
        mocker.patch.object(users_collection, 'find_one', return_value=None)
    
        # Call the login function
        response = login()
    
        # Assert that the user is not redirected
        assert response.location is None
    
        # Assert that the flash message is displayed
        assert 'Login failed. Please check your email and password.' in flask.session['_flashes']
    
        # Assert that the users_collection.find_one() method is called with the correct arguments
        users_collection.find_one.assert_called_once_with({'email': 'test@example.com', 'password': 'password'})

    # TOTP token email fails to send and user receives error message
    def test_failed_email_send(self, mocker):
        # Mock the request form data
        mocker.patch.object(request, 'form', {'email': 'test@example.com', 'password': 'password'})
    
        # Mock the users_collection.find_one() method to return a user
        mocker.patch.object(users_collection, 'find_one', return_value={'email': 'test@example.com', 'password': 'password'})
    
        # Mock the SendGridAPIClient.send() method to raise an exception
        mocker.patch.object(SendGridAPIClient, 'send', side_effect=Exception)
    
        # Call the login function
        response = login()
    
        # Assert that the user is not redirected
        assert response.location is None
    
        # Assert that the flash message is displayed
        assert 'Failed to send the TOTP token.' in flask.session['_flashes']
    
        # Assert that the SendGridAPIClient.send() method is called with the correct arguments
        SendGridAPIClient.send.assert_called_once_with(mocker.ANY)
    
        # Assert that the users_collection.find_one() method is called with the correct arguments
        users_collection.find_one.assert_called_once_with({'email': 'test@example.com', 'password': 'password'})

    # TOTP token email is sent to an invalid email and user receives error message
    def test_invalid_email(self, mocker):
        # Mock the request form data
        mocker.patch.object(request, 'form', {'email': 'test@example.com', 'password': 'password'})
    
        # Mock the users_collection.find_one() method to return a user
        mocker.patch.object(users_collection, 'find_one', return_value={'email': 'test@example.com', 'password': 'password'})
    
        # Mock the SendGridAPIClient.send() method to return a successful response
        mocker.patch.object(SendGridAPIClient, 'send', return_value='success')
    
        # Call the login function
        response = login()
    
        # Assert that the user is not redirected
        assert response.location is None
    
        # Assert that the flash message is displayed
        assert 'Failed to send the TOTP token.' in flask.session['_flashes']
    
        # Assert that the SendGridAPIClient.send() method is called with the correct arguments
        SendGridAPIClient.send.assert_called_once_with(mocker.ANY)
    
        # Assert that the users_collection.find_one() method is called with the correct arguments
        users_collection.find_one.assert_called_once_with({'email': 'test@example.com', 'password': 'password'})

    # User enters incorrect TOTP token and receives error message
    def test_incorrect_totp_token(self, mocker):
        # Mock the request form data
        mocker.patch.object(request, 'form', {'email': 'test@example.com', 'password': 'password', 'totp_token': '123456'})
    
        # Mock the users_collection.find_one() method to return a user
        mocker.patch.object(users_collection, 'find_one', return_value={'email': 'test@example.com', 'password': 'password'})
    
        # Mock the pyotp.TOTP.verify() method to return False
        mocker.patch.object(pyotp.TOTP, 'verify', return_value=False)
    
        # Call the login function
        response = login()
    
        # Assert that the user is not redirected
        assert response.location is None
    
        # Assert that the flash message is displayed
        assert 'Incorrect TOTP token. Please try again.' in flask.session['_flashes']
    
        # Assert that the pyotp.TOTP.verify() method is called with the correct arguments
        pyotp.TOTP.verify.assert_called_once_with('123456')
    
        # Assert that the users_collection.find_one() method is called with the correct arguments
        users_collection.find_one.assert_called_once_with({'email': 'test@example.com', 'password': 'password'})