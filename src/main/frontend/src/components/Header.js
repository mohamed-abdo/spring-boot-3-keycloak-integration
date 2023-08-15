import React from 'react';
import { useHistory } from 'react-router-dom';
import axios from 'axios';
import axios from 'axios';

const Header = () => {
  const history = useHistory();

  const handleLogout = async () => {
    try {
      await axios.post('/logout');
      localStorage.removeItem('user');
      history.push('/login');
    } catch (error) {
      console.error('Error during logout', error);
    }
  };

  return (
    <header>
      <button onClick={handleLogout}>Logout</button>
    </header>
  );
};

export default Header;

