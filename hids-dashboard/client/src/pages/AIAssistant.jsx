import { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Send, Bot, User, Loader, AlertCircle, CheckCircle, RefreshCw, Trash2 } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

const FIXED_MODEL = 'phi3';
const AI_MESSAGES_KEY = 'hids_ai_messages';
const AI_ACTIVE_CHAT_JOB_KEY = 'hids_ai_active_chat_job';

const AIAssistant = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [messages, setMessages] = useState(() => {
    try {
      const raw = localStorage.getItem(AI_MESSAGES_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
    }
  });
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [ollamaStatus, setOllamaStatus] = useState(null);
  const [clearStatus, setClearStatus] = useState('');
  const messagesEndRef = useRef(null);
  const chatPollRef = useRef(null);

  const stopChatPolling = () => {
    if (chatPollRef.current) {
      clearInterval(chatPollRef.current);
      chatPollRef.current = null;
    }
  };

  const clearActiveChatJob = () => {
    localStorage.removeItem(AI_ACTIVE_CHAT_JOB_KEY);
  };

  const appendMessage = (message) => {
    setMessages((prev) => [...prev, message]);
  };

  const startChatPolling = (jobId) => {
    stopChatPolling();
    chatPollRef.current = setInterval(async () => {
      try {
        const response = await axios.get(`/api/ai/chat/status/${jobId}`);
        const job = response.data;

        if (job.status === 'completed') {
          appendMessage({
            role: 'assistant',
            content: job.result?.response || '',
            model: job.result?.model || FIXED_MODEL
          });
          stopChatPolling();
          clearActiveChatJob();
          setLoading(false);
          return;
        }

        if (job.status === 'failed') {
          appendMessage({
            role: 'error',
            content: job.error || 'Failed to get response'
          });
          stopChatPolling();
          clearActiveChatJob();
          setLoading(false);
        }
      } catch (error) {
        appendMessage({
          role: 'error',
          content: error.response?.data?.message || 'Failed to get response'
        });
        stopChatPolling();
        clearActiveChatJob();
        setLoading(false);
      }
    }, 1500);
  };

  useEffect(() => {
    checkOllamaStatus();

    try {
      const rawJob = localStorage.getItem(AI_ACTIVE_CHAT_JOB_KEY);
      if (rawJob) {
        const parsed = JSON.parse(rawJob);
        if (parsed?.jobId) {
          setLoading(true);
          startChatPolling(parsed.jobId);
        }
      }
    } catch {
      clearActiveChatJob();
    }

    return () => {
      stopChatPolling();
    };
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    try {
      localStorage.setItem(AI_MESSAGES_KEY, JSON.stringify(messages));
    } catch {
      // ignore storage errors
    }
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const checkOllamaStatus = async () => {
    try {
      const response = await axios.get('/api/ai/status');
      setOllamaStatus(response.data);
    } catch (error) {
      setOllamaStatus({ connected: false, error: 'Cannot connect to server' });
    }
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMessage = input.trim();
    setInput('');
    appendMessage({ role: 'user', content: userMessage });
    setLoading(true);

    try {
      const response = await axios.post('/api/ai/chat/start', {
        message: userMessage,
        model: FIXED_MODEL
      });

      const jobId = response.data.jobId;
      localStorage.setItem(AI_ACTIVE_CHAT_JOB_KEY, JSON.stringify({ jobId, createdAt: Date.now() }));
      startChatPolling(jobId);
    } catch (error) {
      appendMessage({
        role: 'error',
        content: error.response?.data?.message || 'Failed to get response'
      });
      clearActiveChatJob();
      setLoading(false);
      stopChatPolling();
    }
  };

  const analyzeUrl = async (url) => {
    setLoading(true);
    setMessages(prev => [...prev, { role: 'user', content: `Analyze URL: ${url}` }]);

    try {
      const response = await axios.post('/api/ai/analyze-url', { url });
      const analysis = response.data.analysis;
      
      let content = '';
      if (analysis.raw) {
        content = analysis.raw;
      } else {
        content = `**URL Analysis Results**\n\n`;
        content += `🎯 **Attack Type:** ${analysis.attackType || 'Unknown'}\n`;
        content += `⚠️ **Risk Level:** ${analysis.riskLevel || 'Unknown'}\n`;
        content += `🔍 **Patterns:** ${analysis.patterns || 'N/A'}\n`;
        content += `📋 **Action:** ${analysis.action || 'N/A'}\n`;
        if (analysis.explanation) {
          content += `\n📝 **Explanation:** ${analysis.explanation}`;
        }
      }

      setMessages(prev => [...prev, { role: 'assistant', content, isAnalysis: true }]);
    } catch (error) {
      setMessages(prev => [...prev, {
        role: 'error',
        content: 'URL analysis failed: ' + (error.response?.data?.message || error.message)
      }]);
    } finally {
      setLoading(false);
    }
  };

  const quickPrompts = [
    "What is SQL injection and how to detect it?",
    "Explain XSS attack patterns",
    "How to identify path traversal attacks?",
    "What are signs of a command injection attack?",
    "Best practices for URL security validation"
  ];

  const hasUserRequests = messages.some((message) => message.role === 'user');

  const handleClearChat = () => {
    if (!hasUserRequests) {
      setClearStatus('Nothing to clear');
      return;
    }

    stopChatPolling();
    clearActiveChatJob();
    setLoading(false);
    setMessages([]);
    setClearStatus('Cleared previous requests');
  };

  useEffect(() => {
    if (!clearStatus) return;
    const timeout = setTimeout(() => setClearStatus(''), 2200);
    return () => clearTimeout(timeout);
  }, [clearStatus]);

  const shellClass = isDark
    ? 'bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 border-slate-700/70 shadow-slate-950/50'
    : 'bg-gradient-to-b from-slate-100 via-white to-slate-100 border-slate-200 shadow-slate-300/50';

  const headerClass = isDark
    ? 'bg-gradient-to-r from-slate-800/95 via-slate-800/90 to-slate-900/95 border-slate-700/70'
    : 'bg-gradient-to-r from-white/95 via-slate-50/95 to-white/95 border-slate-200';

  const messageAreaClass = isDark
    ? 'bg-gradient-to-b from-slate-900/70 via-slate-900/50 to-slate-950/80'
    : 'bg-gradient-to-b from-white/80 via-slate-50/60 to-white/90';

  const inputAreaClass = isDark
    ? 'bg-gradient-to-r from-slate-800/95 via-slate-800/92 to-slate-900/95 border-slate-700/70'
    : 'bg-gradient-to-r from-white/95 via-slate-50/95 to-white/95 border-slate-200';

  return (
    <div className={`flex flex-col h-[calc(100vh-120px)] rounded-2xl border overflow-hidden shadow-2xl transition-colors duration-300 ${shellClass}`}>
      {/* Header */}
      <div className={`border-b backdrop-blur-sm p-4 transition-colors duration-300 ${headerClass}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
              <Bot size={24} />
            </div>
            <div>
              <h1 className={`text-xl font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>AI Security Assistant</h1>
              <p className={`text-sm ${isDark ? 'text-gray-400' : 'text-slate-500'}`}>Powered by Phi3 (Ollama)</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleClearChat}
              className={`inline-flex items-center gap-2 px-3 py-2 rounded-lg border transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${
                isDark
                  ? 'border-slate-600 text-slate-200 hover:bg-slate-700/80 disabled:hover:bg-transparent'
                  : 'border-slate-300 text-slate-700 hover:bg-slate-100 disabled:hover:bg-transparent'
              }`}
              disabled={!hasUserRequests}
              title={hasUserRequests ? 'Clear all previous requests' : 'Nothing to clear'}
            >
              <Trash2 size={16} />
              <span className="text-sm font-medium">Clear</span>
            </button>

            {/* Status Badge */}
            <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-sm ${
              ollamaStatus?.connected
                ? 'bg-green-500/20 text-green-400'
                : 'bg-red-500/20 text-red-400'
            }`}>
              {ollamaStatus?.connected ? (
                <>
                  <CheckCircle size={14} />
                  <span>Connected</span>
                </>
              ) : (
                <>
                  <AlertCircle size={14} />
                  <span>Disconnected</span>
                </>
              )}
            </div>

            <button
              onClick={checkOllamaStatus}
              className={`p-2 rounded-lg transition-colors ${
                isDark
                  ? 'text-gray-400 hover:text-white hover:bg-slate-700/80'
                  : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100'
              }`}
              title="Refresh status"
            >
              <RefreshCw size={18} />
            </button>
          </div>
        </div>
        {clearStatus && (
          <p className={`mt-3 text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            {clearStatus}
          </p>
        )}
      </div>

      {/* Ollama Not Connected Warning */}
      {ollamaStatus && !ollamaStatus.connected && (
        <div className="bg-yellow-500/10 border-b border-yellow-500/30 p-4">
          <div className="flex items-start gap-3">
            <AlertCircle className="text-yellow-400 flex-shrink-0 mt-0.5" size={20} />
            <div>
              <p className="text-yellow-400 font-medium">Ollama is not running</p>
              <p className="text-yellow-300/80 text-sm mt-1">
                To use the AI assistant, please start Ollama:
              </p>
              <code className="block mt-2 bg-gray-800 text-green-400 px-3 py-2 rounded text-sm font-mono">
                ollama serve
              </code>
              <p className="text-gray-400 text-sm mt-2">
                If you don't have Ollama installed, visit: 
                <a href="https://ollama.ai" target="_blank" rel="noopener noreferrer" className="text-blue-400 ml-1 hover:underline">
                  ollama.ai
                </a>
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Messages Area */}
      <div className={`flex-1 overflow-y-auto p-4 space-y-4 transition-colors duration-300 ${messageAreaClass}`}>
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <Bot size={48} className={`mb-4 ${isDark ? 'text-gray-600' : 'text-slate-400'}`} />
            <h2 className={`text-xl font-semibold mb-2 ${isDark ? 'text-gray-300' : 'text-slate-700'}`}>
              How can I help you with security analysis?
            </h2>
            <p className={`mb-6 max-w-md ${isDark ? 'text-gray-500' : 'text-slate-500'}`}>
              I can help you understand attack patterns, analyze URLs for threats, 
              and provide security recommendations.
            </p>

            {/* Quick Prompts */}
            <div className="flex flex-wrap gap-2 justify-center max-w-2xl">
              {quickPrompts.map((prompt, idx) => (
                <button
                  key={idx}
                  onClick={() => setInput(prompt)}
                  className={`px-4 py-2 rounded-lg transition-colors text-sm border ${
                    isDark
                      ? 'bg-slate-800/80 text-gray-300 hover:bg-slate-700/90 border-slate-700/60'
                      : 'bg-white text-slate-700 hover:bg-slate-100 border-slate-200'
                  }`}
                >
                  {prompt}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            {msg.role !== 'user' && (
              <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 ${
                msg.role === 'error' ? 'bg-red-500/20' : 'bg-blue-500/20'
              }`}>
                {msg.role === 'error' ? (
                  <AlertCircle size={18} className="text-red-400" />
                ) : (
                  <Bot size={18} className="text-blue-400" />
                )}
              </div>
            )}

            <div className={`max-w-[80%] rounded-lg p-4 ${
              msg.role === 'user'
                ? 'bg-blue-600 text-white'
                : msg.role === 'error'
                ? 'bg-red-500/10 border border-red-500/30 text-red-400'
                : isDark
                ? 'bg-slate-800/85 border border-slate-700/70 text-gray-100'
                : 'bg-white border border-slate-200 text-slate-700'
            }`}>
              <div className="whitespace-pre-wrap">{msg.content}</div>
              {msg.model && (
                <div className={`text-xs mt-2 ${isDark ? 'text-gray-400' : 'text-slate-500'}`}>Model: {msg.model}</div>
              )}
            </div>

            {msg.role === 'user' && (
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center flex-shrink-0">
                <User size={18} />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-3">
            <div className="w-8 h-8 rounded-full bg-blue-500/20 flex items-center justify-center">
              <Bot size={18} className="text-blue-400" />
            </div>
            <div className={`rounded-lg p-4 flex items-center gap-2 border ${
              isDark ? 'bg-gray-800 border-slate-700/60' : 'bg-white border-slate-200'
            }`}>
              <Loader size={18} className="animate-spin text-blue-400" />
              <span className={`${isDark ? 'text-gray-400' : 'text-slate-500'}`}>Thinking...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* URL Analysis Quick Action */}
      {messages.length > 0 && (
        <div className="px-4 pb-2">
          <button
            onClick={() => {
              const url = prompt('Enter URL to analyze:');
              if (url) analyzeUrl(url);
            }}
            className={`text-sm transition-colors ${
              isDark ? 'text-blue-400 hover:text-blue-300' : 'text-blue-600 hover:text-blue-700'
            }`}
          >
            🔍 Quick URL Analysis
          </button>
        </div>
      )}

      {/* Input Area */}
      <form onSubmit={sendMessage} className={`p-4 border-t backdrop-blur-sm transition-colors duration-300 ${inputAreaClass}`}>
        <div className="flex gap-3">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={ollamaStatus?.connected ? "Ask about security threats, attack patterns, or URL analysis..." : "Start Ollama to use the AI assistant"}
            disabled={!ollamaStatus?.connected || loading}
            className={`flex-1 border rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 disabled:opacity-50 disabled:cursor-not-allowed ${
              isDark
                ? 'bg-slate-700/95 text-white border-slate-600'
                : 'bg-white text-slate-900 border-slate-300'
            }`}
          />
          <button
            type="submit"
            disabled={!ollamaStatus?.connected || loading || !input.trim()}
            className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg transition-colors flex items-center gap-2"
          >
            <Send size={20} />
          </button>
        </div>
      </form>
    </div>
  );
};

export default AIAssistant;
