import { createContext, useState, useContext, useCallback, useEffect } from 'react';

const UploadContext = createContext(null);

const MAX_HISTORY = 50; // keep the most recent 50 analyses

// Get user ID from JWT token to create user-specific storage keys
const getUserIdFromToken = () => {
  try {
    const token = localStorage.getItem('token');
    if (!token) return null;
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.user?.id || payload.id || payload.userId || null;
  } catch {
    return null;
  }
};

// Generate user-specific storage keys
const getStorageKeys = (userId) => ({
  latest: userId ? `hids_latest_result_${userId}` : 'hids_latest_result',
  history: userId ? `hids_results_history_${userId}` : 'hids_results_history'
});

const loadFromStorage = (key, fallback) => {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
};

const saveToStorage = (key, value) => {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // localStorage full — ignore
  }
};

export const UploadProvider = ({ children }) => {
  // Get current user ID for user-specific storage
  const [userId, setUserId] = useState(() => getUserIdFromToken());
  const storageKeys = getStorageKeys(userId);

  // Latest completed analysis result
  const [latestResult, setLatestResult] = useState(() => 
    loadFromStorage(storageKeys.latest, null)
  );

  // Full history of all analyses (newest first)
  const [resultsHistory, setResultsHistory] = useState(() => 
    loadFromStorage(storageKeys.history, [])
  );

  // Re-load data when user changes (login/logout)
  useEffect(() => {
    const checkUser = () => {
      const newUserId = getUserIdFromToken();
      if (newUserId !== userId) {
        setUserId(newUserId);
        const newKeys = getStorageKeys(newUserId);
        setLatestResult(loadFromStorage(newKeys.latest, null));
        setResultsHistory(loadFromStorage(newKeys.history, []));
      }
    };

    // Check on storage changes (for multi-tab sync)
    window.addEventListener('storage', checkUser);
    
    // Check periodically for token changes
    const interval = setInterval(checkUser, 1000);

    return () => {
      window.removeEventListener('storage', checkUser);
      clearInterval(interval);
    };
  }, [userId]);

  const saveResult = useCallback((result) => {
    const keys = getStorageKeys(getUserIdFromToken());
    
    // Update latest
    setLatestResult(result);
    saveToStorage(keys.latest, result);

    // Add to history (de-duplicate by upload_id)
    setResultsHistory(prev => {
      const filtered = prev.filter(r => r.upload_id !== result.upload_id);
      const updated = [result, ...filtered].slice(0, MAX_HISTORY);
      saveToStorage(keys.history, updated);
      return updated;
    });
  }, []);

  const clearResult = useCallback(() => {
    const keys = getStorageKeys(getUserIdFromToken());
    setLatestResult(null);
    localStorage.removeItem(keys.latest);
  }, []);

  const clearHistory = useCallback(() => {
    const keys = getStorageKeys(getUserIdFromToken());
    setResultsHistory([]);
    localStorage.removeItem(keys.history);
  }, []);

  const removeFromHistory = useCallback((uploadId) => {
    const keys = getStorageKeys(getUserIdFromToken());
    setResultsHistory(prev => {
      const updated = prev.filter(r => r.upload_id !== uploadId);
      saveToStorage(keys.history, updated);
      return updated;
    });
  }, []);

  return (
    <UploadContext.Provider value={{
      latestResult,
      resultsHistory,
      saveResult,
      clearResult,
      clearHistory,
      removeFromHistory
    }}>
      {children}
    </UploadContext.Provider>
  );
};

export const useUpload = () => {
  const ctx = useContext(UploadContext);
  if (!ctx) throw new Error('useUpload must be used within UploadProvider');
  return ctx;
};
