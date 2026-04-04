import { createContext, useState, useEffect, useContext } from 'react';
import axios from 'axios';
import { AuthContext } from './AuthContext';

export const ThemeContext = createContext();

export const ThemeProvider = ({ children }) => {
  const { user, token } = useContext(AuthContext);
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('theme') || 'dark';
  });

  // Sync theme with user preference when logged in
  useEffect(() => {
    if (user?.theme) {
      setTheme(user.theme);
      localStorage.setItem('theme', user.theme);
    }
  }, [user]);

  // Apply theme to document
  useEffect(() => {
    const root = document.documentElement;
    const body = document.body;
    
    if (theme === 'dark') {
      root.classList.add('dark');
      root.classList.remove('light');
      body.classList.add('dark');
      body.classList.remove('light');
      body.style.backgroundColor = '#111827';
      body.style.color = '#f9fafb';
    } else {
      root.classList.remove('dark');
      root.classList.add('light');
      body.classList.remove('dark');
      body.classList.add('light');
      body.style.backgroundColor = '#f9fafb';
      body.style.color = '#111827';
    }
    localStorage.setItem('theme', theme);
  }, [theme]);

  const toggleTheme = async () => {
    const newTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);

    if (token) {
      try {
        await axios.put('/api/profile/theme', { theme: newTheme });
      } catch (error) {
        console.error('Failed to sync theme:', error);
      }
    }
  };

  const setThemeValue = async (newTheme) => {
    setTheme(newTheme);

    if (token) {
      try {
        await axios.put('/api/profile/theme', { theme: newTheme });
      } catch (error) {
        console.error('Failed to sync theme:', error);
      }
    }
  };

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme, setTheme: setThemeValue }}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};
