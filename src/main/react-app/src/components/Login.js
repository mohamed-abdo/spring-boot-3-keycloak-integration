import React, { useState, useEffect } from 'react';
import axios from 'axios';

function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loginStatus, setLoginStatus] = useState('');

  useEffect(() => {
    const login = async () => {
      const response = await axios.post('http://localhost:8080/login', {
        username,
        password
      });
      console.log(response);
      if (response.status === 200) {
        setLoginStatus('Login successful');
      } else {
        setLoginStatus('Login failed');
      }
    };

    login();
  }, []);

  return (
    <div>
      <form>
        <input type="text" value={username} onChange={e => setUsername(e.target.value)} />
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} />
        <button type="submit">Login</button>
      </form>
    </div>
  );
}

export default Login;

