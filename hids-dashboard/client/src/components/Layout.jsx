import { useEffect, useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import axios from 'axios';
import { CheckCircle } from 'lucide-react';
import Sidebar from './Sidebar';

const getUserIdFromToken = () => {
  try {
    const token = sessionStorage.getItem('token') || localStorage.getItem('token');
    if (!token) return null;
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.user?.id || payload.id || payload.userId || null;
  } catch {
    return null;
  }
};

const Layout = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [notification, setNotification] = useState({ visible: false, message: '' });
  const location = useLocation();

  useEffect(() => {
    if (location.pathname.startsWith('/app/ai')) {
      return undefined;
    }

    const userId = getUserIdFromToken();
    const activeKey = userId ? `hids_ai_active_chat_job_${userId}` : 'hids_ai_active_chat_job_anonymous';
    const messagesKey = userId ? `hids_ai_messages_${userId}` : 'hids_ai_messages_anonymous';

    const interval = setInterval(async () => {
      try {
        const rawJob = localStorage.getItem(activeKey);
        if (!rawJob) return;

        const parsed = JSON.parse(rawJob);
        if (!parsed?.jobId) {
          localStorage.removeItem(activeKey);
          return;
        }

        const response = await axios.get(`/api/ai/chat/status/${parsed.jobId}`);
        const job = response.data;

        if (job.status === 'completed') {
          const assistantMessage = {
            role: 'assistant',
            content: job.result?.response || '',
            model: job.result?.model || 'phi3'
          };

          try {
            const rawMessages = localStorage.getItem(messagesKey);
            const existing = rawMessages ? JSON.parse(rawMessages) : [];
            const last = existing[existing.length - 1];
            const duplicateLast = last
              && last.role === assistantMessage.role
              && last.content === assistantMessage.content
              && last.model === assistantMessage.model;
            const nextMessages = duplicateLast ? existing : [...existing, assistantMessage];
            localStorage.setItem(messagesKey, JSON.stringify(nextMessages));
          } catch {
            // ignore storage errors
          }

          localStorage.removeItem(activeKey);
          setNotification({ visible: true, message: 'AI response is ready' });
          return;
        }

        if (job.status === 'failed') {
          localStorage.removeItem(activeKey);
        }
      } catch {
        // Keep polling silently; network/server blips should not break layout.
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [location.pathname]);

  useEffect(() => {
    if (!notification.visible) return undefined;
    const timeout = setTimeout(() => {
      setNotification((prev) => ({ ...prev, visible: false }));
    }, 3000);
    return () => clearTimeout(timeout);
  }, [notification.visible]);

  return (
    <div className="flex min-h-screen">
      {notification.visible && (
        <div className="fixed top-4 right-4 z-[80] max-w-sm">
          <div className="flex items-center gap-3 rounded-xl border px-4 py-3 shadow-lg backdrop-blur-md bg-emerald-50/95 border-emerald-200 text-emerald-800">
            <CheckCircle size={18} className="text-emerald-600" />
            <p className="text-sm font-medium">{notification.message}</p>
          </div>
        </div>
      )}

      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} />
      <main className={`flex-1 transition-all duration-500 ease-in-out ${collapsed ? 'lg:ml-20' : 'lg:ml-64'}`}>
        <div className="p-6 lg:p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
};

export default Layout;
