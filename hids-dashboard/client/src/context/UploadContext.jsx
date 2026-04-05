import { createContext, useState, useContext, useCallback } from 'react';

const UploadContext = createContext(null);

const STORAGE_KEY_LATEST = 'hids_latest_result';
const STORAGE_KEY_HISTORY = 'hids_results_history';
const MAX_HISTORY = 50; // keep the most recent 50 analyses

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
  // Latest completed analysis result
  const [latestResult, setLatestResult] = useState(() => loadFromStorage(STORAGE_KEY_LATEST, null));

  // Full history of all analyses (newest first)
  const [resultsHistory, setResultsHistory] = useState(() => loadFromStorage(STORAGE_KEY_HISTORY, []));

  const saveResult = useCallback((result) => {
    // Update latest
    setLatestResult(result);
    saveToStorage(STORAGE_KEY_LATEST, result);

    // Add to history (de-duplicate by upload_id)
    setResultsHistory(prev => {
      const filtered = prev.filter(r => r.upload_id !== result.upload_id);
      const updated = [result, ...filtered].slice(0, MAX_HISTORY);
      saveToStorage(STORAGE_KEY_HISTORY, updated);
      return updated;
    });
  }, []);

  const clearResult = useCallback(() => {
    setLatestResult(null);
    localStorage.removeItem(STORAGE_KEY_LATEST);
  }, []);

  const clearHistory = useCallback(() => {
    setResultsHistory([]);
    localStorage.removeItem(STORAGE_KEY_HISTORY);
  }, []);

  const removeFromHistory = useCallback((uploadId) => {
    setResultsHistory(prev => {
      const updated = prev.filter(r => r.upload_id !== uploadId);
      saveToStorage(STORAGE_KEY_HISTORY, updated);
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
