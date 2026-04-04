import { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Send, Bot, User, Loader, AlertCircle, CheckCircle, RefreshCw } from 'lucide-react';

const AIAssistant = () => {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [ollamaStatus, setOllamaStatus] = useState(null);
  const [models, setModels] = useState([]);
  const [selectedModel, setSelectedModel] = useState('');
  const messagesEndRef = useRef(null);

  useEffect(() => {
    checkOllamaStatus();
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const checkOllamaStatus = async () => {
    try {
      const response = await axios.get('/api/ai/status');
      setOllamaStatus(response.data);
      if (response.data.connected && response.data.models) {
        setModels(response.data.models);
        setSelectedModel(response.data.defaultModel || response.data.models[0]?.name);
      }
    } catch (error) {
      setOllamaStatus({ connected: false, error: 'Cannot connect to server' });
    }
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMessage = input.trim();
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setLoading(true);

    try {
      const response = await axios.post('/api/ai/chat', {
        message: userMessage,
        model: selectedModel
      });

      setMessages(prev => [...prev, {
        role: 'assistant',
        content: response.data.response,
        model: response.data.model
      }]);
    } catch (error) {
      setMessages(prev => [...prev, {
        role: 'error',
        content: error.response?.data?.message || 'Failed to get response'
      }]);
    } finally {
      setLoading(false);
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

  return (
    <div className="flex flex-col h-[calc(100vh-120px)] bg-gray-900">
      {/* Header */}
      <div className="bg-gray-800 border-b border-gray-700 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
              <Bot size={24} />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">AI Security Assistant</h1>
              <p className="text-sm text-gray-400">Powered by Phi3 (Ollama)</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Model Selector */}
            {models.length > 0 && (
              <select
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
                className="bg-gray-700 text-white border border-gray-600 rounded-lg px-3 py-2 text-sm"
              >
                {models.map(model => (
                  <option key={model.name} value={model.name}>{model.name}</option>
                ))}
              </select>
            )}

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
              className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
              title="Refresh status"
            >
              <RefreshCw size={18} />
            </button>
          </div>
        </div>
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
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <Bot size={48} className="text-gray-600 mb-4" />
            <h2 className="text-xl font-semibold text-gray-300 mb-2">
              How can I help you with security analysis?
            </h2>
            <p className="text-gray-500 mb-6 max-w-md">
              I can help you understand attack patterns, analyze URLs for threats, 
              and provide security recommendations.
            </p>

            {/* Quick Prompts */}
            <div className="flex flex-wrap gap-2 justify-center max-w-2xl">
              {quickPrompts.map((prompt, idx) => (
                <button
                  key={idx}
                  onClick={() => setInput(prompt)}
                  className="px-4 py-2 bg-gray-800 text-gray-300 rounded-lg hover:bg-gray-700 transition-colors text-sm"
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
                : 'bg-gray-800 text-gray-100'
            }`}>
              <div className="whitespace-pre-wrap">{msg.content}</div>
              {msg.model && (
                <div className="text-xs text-gray-400 mt-2">Model: {msg.model}</div>
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
            <div className="bg-gray-800 rounded-lg p-4 flex items-center gap-2">
              <Loader size={18} className="animate-spin text-blue-400" />
              <span className="text-gray-400">Thinking...</span>
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
            className="text-sm text-blue-400 hover:text-blue-300 transition-colors"
          >
            🔍 Quick URL Analysis
          </button>
        </div>
      )}

      {/* Input Area */}
      <form onSubmit={sendMessage} className="p-4 bg-gray-800 border-t border-gray-700">
        <div className="flex gap-3">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={ollamaStatus?.connected ? "Ask about security threats, attack patterns, or URL analysis..." : "Start Ollama to use the AI assistant"}
            disabled={!ollamaStatus?.connected || loading}
            className="flex-1 bg-gray-700 text-white border border-gray-600 rounded-lg px-4 py-3 focus:outline-none focus:border-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
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
