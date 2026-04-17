import { createContext, useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const MIN_AUTH_LOADING_MS = 1000;
const INTRO_LOADER_KEY = 'hids_intro_loader_shown';

const getIntroDelayMs = () => {
  try {
    const shown = sessionStorage.getItem(INTRO_LOADER_KEY) === '1';
    if (shown) return 0;
    sessionStorage.setItem(INTRO_LOADER_KEY, '1');
    return MIN_AUTH_LOADING_MS;
  } catch {
    // If sessionStorage is unavailable, gracefully fall back to no forced delay.
    return 0;
  }
};

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  // Set axios Authorization header
  useEffect(() => {
    const delayMs = getIntroDelayMs();
    const startedAt = Date.now();

    const finishLoading = async () => {
      const elapsed = Date.now() - startedAt;
      const remaining = Math.max(0, delayMs - elapsed);
      if (remaining > 0) {
        await new Promise((resolve) => setTimeout(resolve, remaining));
      }
      setLoading(false);
    };

    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      validateToken(finishLoading);
    } else {
      delete axios.defaults.headers.common['Authorization'];
      finishLoading();
    }
  }, [token]);

  // Global axios interceptor for 401 responses (skip auth endpoints)
  useEffect(() => {
    const interceptor = axios.interceptors.response.use(
      (response) => response,
      (error) => {
        const url = error.config?.url || '';
        // Don't logout on auth endpoints - let them handle their own errors
        if (error.response?.status === 401 && !url.includes('/api/auth/')) {
          logout();
        }
        return Promise.reject(error);
      }
    );

    return () => axios.interceptors.response.eject(interceptor);
  }, []);

  const validateToken = async (onFinish) => {
    try {
      const response = await axios.get('/api/auth/me');
      setUser(response.data);
    } catch (error) {
      console.error('Token validation failed:', error);
      localStorage.removeItem('token');
      setToken(null);
      setUser(null);
    } finally {
      await onFinish();
    }
  };

  const login = async (email, password) => {
    const response = await axios.post('/api/auth/login', { email, password });
    const { token: newToken, user: userData } = response.data;

    localStorage.setItem('token', newToken);
    setToken(newToken);
    setUser(userData);

    return userData;
  };

  const register = async (username, email, password) => {
    const response = await axios.post('/api/auth/register', { username, email, password });
    const { token: newToken, user: userData } = response.data;

    localStorage.setItem('token', newToken);
    setToken(newToken);
    setUser(userData);

    return userData;
  };

  const logout = () => {
    localStorage.removeItem('token');
    // Clear old shared storage keys (from before user-isolation update)
    localStorage.removeItem('hids_latest_result');
    localStorage.removeItem('hids_results_history');
    setToken(null);
    setUser(null);
    delete axios.defaults.headers.common['Authorization'];
  };

  return (
    <AuthContext.Provider value={{ user, token, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
};
