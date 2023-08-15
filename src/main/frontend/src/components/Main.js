import React, { useState, useEffect } from 'react';
import { useHistory } from 'react-router-dom';

const Main = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const history = useHistory();

  useEffect(() => {
    const user = localStorage.getItem('user');
    if (user) {
      setIsAuthenticated(true);
    } else {
      history.push('/login');
    }
  }, [history]);

  if (!isAuthenticated) {
    return null;
  }

  return (
    <div>
      <h1>Welcome to the Main Page!</h1>
      <p>This is the main content of the application.</p>
    </div>
  );
};

export default Main;

