from login import signup

import pytest

class TestSignup:
    # User submits a valid email and password, and the account is created successfully.
    def test_valid_email_and_password(self, mocker):
        mocker.patch('flask.request')
        mocker.patch('flask.flash')
        mocker.patch('flask.redirect')
        mocker.patch('flask.url_for')
        mocker.patch('flask.render_template')
        mocker.patch('flask.request.method', return_value='POST')
        mocker.patch('flask.request.form', {'email': 'test@example.com', 'password': 'password'})
        mocker.patch('users_collection.find_one', return_value=None)
        signup()
        users_collection.insert_one.assert_called_once_with({'email': 'test@example.com', 'password': 'password'})
        flask.flash.assert_called_once_with('Account created successfully. Please log in.')
        flask.redirect.assert_called_once_with(flask.url_for('login'))

    # User submits a valid email and password, but the email is already registered, and the user is redirected to the login page.
    def test_existing_email(self, mocker):
        mocker.patch('flask.request')
        mocker.patch('flask.flash')
        mocker.patch('flask.redirect')
        mocker.patch('flask.url_for')
        mocker.patch('flask.render_template')
        mocker.patch('flask.request.method', return_value='POST')
        mocker.patch('flask.request.form', {'email': 'test@example.com', 'password': 'password'})
        mocker.patch('users_collection.find_one', return_value={'email': 'test@example.com'})
        signup()
        flask.flash.assert_called_once_with('Email already registered. Please log in.')
        flask.redirect.assert_called_once_with(flask.url_for('login'))

    # User submits an invalid email format, and an error message is displayed.
    def test_invalid_email_format(self, mocker):
        mocker.patch('flask.request')
        mocker.patch('flask.flash')
        mocker.patch('flask.redirect')
        mocker.patch('flask.url_for')
        mocker.patch('flask.render_template')
        mocker.patch('flask.request.method', return_value='POST')
        mocker.patch('flask.request.form', {'email': 'invalid_email', 'password': 'password'})
        signup()
        flask.flash.assert_called_once_with('Invalid email format.')

    # User submits an invalid password format, and an error message is displayed.
    def test_invalid_password_format(self, mocker):
        mocker.patch('flask.request')
        mocker.patch('flask.flash')
        mocker.patch('flask.redirect')
        mocker.patch('flask.url_for')
        mocker.patch('flask.render_template')
        mocker.patch('flask.request.method', return_value='POST')
        mocker.patch('flask.request.form', {'email': 'test@example.com', 'password': 'pass'})
        signup()
        flask.flash.assert_called_once_with('Invalid password format.')

    # User submits an empty email field, and an error message is displayed.
    def test_empty_email_field(self, mocker):
        mocker.patch('flask.request')
        mocker.patch('flask.flash')
        mocker.patch('flask.redirect')
        mocker.patch('flask.url_for')
        mocker.patch('flask.render_template')
        mocker.patch('flask.request.method', return_value='POST')
        mocker.patch('flask.request.form', {'email': '', 'password': 'password'})
        signup()
        flask.flash.assert_called_once_with('Email field cannot be empty.')

    # User submits an empty password field, and an error message is displayed.
    def test_empty_password_field(self, mocker):
        mocker.patch('flask.request')
        mocker.patch('flask.flash')
        mocker.patch('flask.redirect')
        mocker.patch('flask.url_for')
        mocker.patch('flask.render_template')
        mocker.patch('flask.request.method', return_value='POST')
        mocker.patch('flask.request.form', {'email': 'test@example.com', 'password': ''})
        signup()
        flask.flash.assert_called_once_with('Password field cannot be empty.')