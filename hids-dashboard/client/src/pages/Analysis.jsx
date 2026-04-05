import { RefreshCw } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
import { useApi } from '../hooks/useApi';
import { useTheme } from '../context/ThemeContext';

const Analysis = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const { data: ipData, loading: ipLoading, error: ipError, refetch: refetchIp } = useApi('/api/analysis/ips');
  const { data: features, loading: featuresLoading } = useApi('/api/analysis/features');
  const { data: methods, loading: methodsLoading } = useApi('/api/analysis/methods');

  const getRiskLevelColor = (level) => {
    switch (level) {
      case 'Critical': return 'bg-red-100 text-red-800';
      case 'High': return 'bg-orange-100 text-orange-800';
      case 'Medium': return 'bg-yellow-100 text-yellow-800';
      case 'Low': return 'bg-green-100 text-green-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const METHOD_COLORS = {
    'Regex': '#ef4444',
    'Machine Learning': '#3b82f6',
    'Statistical': '#22c55e'
  };

  if (ipLoading || featuresLoading || methodsLoading) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold text-gray-900">Analysis</h1>
        <div className="space-y-6">
          <div className="skeleton h-96 rounded-xl" />
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="skeleton h-80 rounded-xl" />
            <div className="skeleton h-80 rounded-xl" />
          </div>
        </div>
      </div>
    );
  }

  if (ipError) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold text-gray-900">Analysis</h1>
        <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-center">
          <p className="text-red-800 mb-4">{ipError}</p>
          <button
            onClick={refetchIp}
            className="inline-flex items-center space-x-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
          >
            <RefreshCw size={16} />
            <span>Retry</span>
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Analysis</h1>
        <button
          onClick={refetchIp}
          className={`inline-flex items-center space-x-2 px-4 py-2 border rounded-lg transition-colors ${
            isDark
              ? 'bg-gray-800 text-gray-200 border-gray-600 hover:bg-gray-700'
              : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
          }`}
        >
          <RefreshCw size={16} />
          <span>Refresh</span>
        </button>
      </div>

      {/* IP Risk Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <div className="p-6 border-b border-gray-200">
          <h2 className="text-xl font-semibold text-gray-900">IP Risk Analysis</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">
                  IP Address
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">
                  Total Requests
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">
                  Threats
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">
                  Threat %
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">
                  Risk Level
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {ipData?.map((ip, idx) => (
                <tr key={idx} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-mono font-medium text-gray-900">
                    {ip.ip}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {ip.total}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {ip.threats}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {ip.threat_percentage}%
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-3 py-1 text-xs font-semibold rounded-full ${getRiskLevelColor(ip.risk_level)}`}>
                      {ip.risk_level}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {(!ipData || ipData.length === 0) && (
          <div className="text-center py-12 text-gray-400">
            No IP data available
          </div>
        )}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Feature Importance */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Feature Importance</h2>
          {features && features.length > 0 ? (
            <ResponsiveContainer width="100%" height={350}>
              <BarChart data={features} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis
                  dataKey="feature"
                  type="category"
                  width={120}
                  tick={{ fontSize: 12 }}
                />
                <Tooltip />
                <Bar dataKey="importance" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[350px] flex items-center justify-center text-gray-400">
              No feature data available
            </div>
          )}
        </div>

        {/* Detection Methods */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Detection Method Breakdown</h2>
          {methods && methods.length > 0 ? (
            <ResponsiveContainer width="100%" height={350}>
              <PieChart>
                <Pie
                  data={methods}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ method, count }) => `${method}: ${count}`}
                  outerRadius={100}
                  fill="#8884d8"
                  dataKey="count"
                >
                  {methods.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={METHOD_COLORS[entry.method] || '#6b7280'} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[350px] flex items-center justify-center text-gray-400">
              No method data available
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Analysis;
