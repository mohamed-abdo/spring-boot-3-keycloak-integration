import React from 'react';
import { useHistory } from 'react-router-dom';

const Header = () => {
  const history = useHistory();

  const handleLogout = () => {
    // Clear user's authentication status
    // This is a placeholder and should be replaced with actual logic
    localStorage.removeItem('user');

    // Redirect to login screen
    history.push('/login');
  };

  return (
    <header>
      <button onClick={handleLogout}>Logout</button>
    </header>
  );
};

export default Header;

