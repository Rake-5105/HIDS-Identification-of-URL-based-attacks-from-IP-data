import { useState, useEffect } from 'react';
import axios from 'axios';

export const useApi = (url, options = {}) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const { transform, skip } = options;

  const fetchData = async () => {
    if (skip) {
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    const controller = new AbortController();
    const token = localStorage.getItem('token');

    try {
      const response = await axios.get(url, {
        signal: controller.signal,
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      });

      const result = transform ? transform(response.data) : response.data;
      setData(result);
    } catch (err) {
      if (!axios.isCancel(err)) {
        setError(err.response?.data?.message || err.message || 'An error occurred');
      }
    } finally {
      setLoading(false);
    }

    return () => controller.abort();
  };

  useEffect(() => {
    fetchData();
  }, [url, skip]);

  const refetch = () => {
    fetchData();
  };

  return { data, loading, error, refetch };
};
