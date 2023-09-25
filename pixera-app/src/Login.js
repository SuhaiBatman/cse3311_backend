import React from 'react';
import { GoogleLogin } from 'react-google-login';

const Login = ({ onLogin }) => {
  	const responseGoogle = (response) => {
		if (response && response.profileObj) {
		onLogin(response.profileObj);
		}
  	};

	/*Might be config not redirect*/
  	return (
		<div className="login-container">
			<h2>Login with Google</h2>
			<GoogleLogin
				clientId="1079550904724-r04lienf30qi77ard9uuafbdeupi2olf.apps.googleusercontent.com"
				clentSecret="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"
				buttonText="Login with Google"
				onSuccess={responseGoogle}
				onFailure={responseGoogle}
				redirectUri='http://localhost:3000/callback'
				cookiePolicy={'single_host_origin'}
			/>
		</div>
	); 
};

export default Login;
