import React, { useState } from 'react';
import './App.css';
import Login from './Login';

function App() {
  const [user, setUser] = useState(null);

  const handleLogin = (profileObj) => {
    setUser(profileObj);
  };

  return (
    <div className="App">
      {user ? (
        <div>
          <h2>Welcome, {user.name}!</h2>
          <img src={user.imageUrl} alt="User" />
        </div>
      ) : (
        <Login onLogin={handleLogin} />
      )}
    </div>
  );
}

export default App;
