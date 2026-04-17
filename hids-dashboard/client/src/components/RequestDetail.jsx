import { X } from 'lucide-react';

export const ATTACK_COLORS = {
  normal: { bg: 'bg-green-100', text: 'text-green-800' },
  sqli: { bg: 'bg-red-100', text: 'text-red-800' },
  'sql injection': { bg: 'bg-red-100', text: 'text-red-800' },
  xss: { bg: 'bg-orange-100', text: 'text-orange-800' },
  'cross-site scripting (xss)': { bg: 'bg-orange-100', text: 'text-orange-800' },
  path_traversal: { bg: 'bg-yellow-100', text: 'text-yellow-800' },
  'directory traversal': { bg: 'bg-yellow-100', text: 'text-yellow-800' },
  cmdi: { bg: 'bg-purple-100', text: 'text-purple-800' },
  'command injection': { bg: 'bg-purple-100', text: 'text-purple-800' },
  phishing: { bg: 'bg-cyan-100', text: 'text-cyan-800' },
  phising: { bg: 'bg-cyan-100', text: 'text-cyan-800' },
  'typosquatting / url spoofing': { bg: 'bg-fuchsia-100', text: 'text-fuchsia-800' },
  'web shell upload': { bg: 'bg-rose-100', text: 'text-rose-800' },
  unknown: { bg: 'bg-gray-100', text: 'text-gray-800' }
};

const RequestDetail = ({ request, onClose, index }) => {
  if (!request) return null;

  const classification = request.classification?.toLowerCase() || 'unknown';
  const colors = ATTACK_COLORS[classification] || ATTACK_COLORS.unknown;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-end">
      <div className="bg-white h-full w-full max-w-2xl shadow-xl overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-white border-b border-gray-200 p-6 flex items-center justify-between">
          <h2 className="text-2xl font-bold text-gray-900">Request Details</h2>
          <button
            onClick={onClose}
            className="p-2 rounded-lg border border-gray-300 bg-white text-gray-700 hover:bg-gray-100 hover:text-gray-900 transition-colors dark:bg-gray-800 dark:border-gray-600 dark:text-gray-100 dark:hover:bg-gray-700"
            aria-label="Close request details"
          >
            <X size={24} />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Classification Badge */}
          <div>
            <span className={`inline-block px-4 py-2 rounded-full text-sm font-semibold ${colors.bg} ${colors.text}`}>
              {classification.toUpperCase()}
            </span>
          </div>

          {/* Request Index */}
          <div>
            <label className="block text-sm font-medium text-gray-600 mb-1">Request Index</label>
            <p className="text-lg text-gray-900">#{index}</p>
          </div>

          {/* Timestamp */}
          {request.timestamp && (
            <div>
              <label className="block text-sm font-medium text-gray-600 mb-1">Timestamp</label>
              <p className="text-lg text-gray-900">{new Date(request.timestamp).toLocaleString()}</p>
            </div>
          )}

          {/* Source IP */}
          {request.source_ip && (
            <div>
              <label className="block text-sm font-medium text-gray-600 mb-1">Source IP</label>
              <p className="text-lg text-gray-900 font-mono">{request.source_ip}</p>
            </div>
          )}

          {/* URL */}
          {request.url && (
            <div>
              <label className="block text-sm font-medium text-gray-600 mb-1">URL</label>
              <div className="bg-gray-50 p-4 rounded-lg border border-gray-200 break-all">
                <code className="text-sm text-gray-900">{request.url}</code>
              </div>
            </div>
          )}

          {/* Confidence */}
          {request.confidence && (
            <div>
              <label className="block text-sm font-medium text-gray-600 mb-2">Confidence</label>
              <div className="flex items-center space-x-3">
                <div className="flex-1 h-4 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-600 transition-all duration-300"
                    style={{ width: `${parseFloat(request.confidence)}%` }}
                  />
                </div>
                <span className="text-sm font-semibold text-gray-900">
                  {parseFloat(request.confidence).toFixed(2)}%
                </span>
              </div>
            </div>
          )}

          {/* Detection Method */}
          {request.detection_method && (
            <div>
              <label className="block text-sm font-medium text-gray-600 mb-1">Detection Method</label>
              <p className="text-lg text-gray-900 capitalize">{request.detection_method}</p>
            </div>
          )}

          {/* Additional Fields */}
          <div>
            <label className="block text-sm font-medium text-gray-600 mb-2">Additional Information</label>
            <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
              <pre className="text-xs text-gray-700 overflow-x-auto">
                {JSON.stringify(request, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RequestDetail;
