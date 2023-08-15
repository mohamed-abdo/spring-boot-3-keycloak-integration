import React, { useState, useEffect } from 'react';
import Header from './Header';
import Login from './Login';
import Main from './Main';

const App = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    const user = localStorage.getItem('user');
    if (user) {
      setIsAuthenticated(true);
    }
  }, []);

  return (
    isAuthenticated ? (
      <>
        <Header />
        <Main />
      </>
    ) : (
      <Login />
    )
  );
};

export default App;

