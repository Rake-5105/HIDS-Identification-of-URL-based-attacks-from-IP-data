import { useEffect, useRef } from 'react';
import { RefreshCw } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
import { useApi } from '../hooks/useApi';
import { useTheme } from '../context/ThemeContext';
import { useUpload } from '../context/UploadContext';

const Analysis = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const { data: ipData, loading: ipLoading, error: ipError, refetch: refetchIp } = useApi('/api/analysis/ips');
  const { data: features, loading: featuresLoading, refetch: refetchFeatures } = useApi('/api/analysis/features');
  const { data: methods, loading: methodsLoading, refetch: refetchMethods } = useApi('/api/analysis/methods');
  const { data: summary, refetch: refetchSummary } = useApi('/api/summary');
  const { latestResult } = useUpload();
  
  // Track last refreshed analysis to prevent infinite loops
  const lastRefreshedRef = useRef(null);

  // Auto-refetch all data when new analysis completes (only once per analysis)
  useEffect(() => {
    const analysisId = latestResult?.analyzedAt;
    if (analysisId && analysisId !== lastRefreshedRef.current) {
      lastRefreshedRef.current = analysisId;
      refetchIp();
      refetchFeatures();
      refetchMethods();
      refetchSummary();
    }
  }, [latestResult?.analyzedAt, refetchIp, refetchFeatures, refetchMethods, refetchSummary]);

  // Unified refresh function
  const handleRefresh = () => {
    refetchIp();
    refetchFeatures();
    refetchMethods();
    refetchSummary();
  };

  const getRiskLevelColor = (level) => {
    if (isDark) {
      switch (level) {
        case 'Critical': return 'bg-red-900/50 text-red-300';
        case 'High': return 'bg-orange-900/50 text-orange-300';
        case 'Medium': return 'bg-yellow-900/50 text-yellow-300';
        case 'Low': return 'bg-green-900/50 text-green-300';
        default: return 'bg-gray-700 text-gray-300';
      }
    }
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

  // Use real data from API only - no random generation
  const effectiveIpData = ipData || [];
  const effectiveFeatures = features || [];
  
  // Filter out zero-count methods for better pie chart
  const effectiveMethods = methods?.filter(m => m.count > 0) || [];

  if (ipLoading || featuresLoading || methodsLoading) {
    return (
      <div className="space-y-6">
        <h1 className={`text-3xl font-bold ${isDark ? 'text-white' : 'text-gray-900'}`}>Analysis</h1>
        <div className="space-y-6">
          <div className={`skeleton h-96 rounded-xl ${isDark ? 'bg-gray-700' : ''}`} />
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className={`skeleton h-80 rounded-xl ${isDark ? 'bg-gray-700' : ''}`} />
            <div className={`skeleton h-80 rounded-xl ${isDark ? 'bg-gray-700' : ''}`} />
          </div>
        </div>
      </div>
    );
  }

  if (ipError) {
    return (
      <div className="space-y-6">
        <h1 className={`text-3xl font-bold ${isDark ? 'text-white' : 'text-gray-900'}`}>Analysis</h1>
        <div className={`${isDark ? 'bg-red-900/30 border-red-700' : 'bg-red-50 border-red-200'} border rounded-xl p-6 text-center`}>
          <p className={`${isDark ? 'text-red-300' : 'text-red-800'} mb-4`}>{ipError}</p>
          <button
            onClick={handleRefresh}
            className="inline-flex items-center space-x-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
          >
            <RefreshCw size={16} />
            <span>Retry</span>
          </button>
        </div>
      </div>
    );
  }

  // Custom label for pie chart - positioned outside for clarity
  const renderPieLabel = ({ cx, cy, midAngle, outerRadius, method, count, percent }) => {
    if (percent < 0.01) return null;
    const RADIAN = Math.PI / 180;
    const radius = outerRadius + 30;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);

    return (
      <text
        x={x}
        y={y}
        fill={isDark ? '#e5e7eb' : '#374151'}
        textAnchor={x > cx ? 'start' : 'end'}
        dominantBaseline="central"
        style={{ fontSize: '12px', fontWeight: '500' }}
      >
        {method}: {count.toLocaleString()}
      </text>
    );
  };

  // Custom tooltip
  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const item = payload[0].payload;
      return (
        <div className={`${isDark ? 'bg-gray-800 text-white' : 'bg-white text-gray-900'} px-3 py-2 rounded-lg shadow-lg text-sm border ${isDark ? 'border-gray-600' : 'border-gray-200'}`}>
          <p className="font-semibold">{item.method}</p>
          <p>{item.count.toLocaleString()} detections</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className={`text-3xl font-bold ${isDark ? 'text-white' : 'text-gray-900'}`}>Analysis</h1>
        <button
          onClick={handleRefresh}
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
      <div className={`${isDark ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} rounded-xl shadow-sm border overflow-hidden`}>
        <div className={`p-6 border-b ${isDark ? 'border-gray-700' : 'border-gray-200'}`}>
          <h2 className={`text-xl font-semibold ${isDark ? 'text-white' : 'text-gray-900'}`}>IP Risk Analysis</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className={`${isDark ? 'bg-gray-900/50 border-gray-700' : 'bg-gray-50 border-gray-200'} border-b`}>
              <tr>
                <th className={`px-6 py-3 text-left text-xs font-medium ${isDark ? 'text-gray-400' : 'text-gray-700'} uppercase tracking-wider`}>
                  IP Address
                </th>
                <th className={`px-6 py-3 text-left text-xs font-medium ${isDark ? 'text-gray-400' : 'text-gray-700'} uppercase tracking-wider`}>
                  Total Requests
                </th>
                <th className={`px-6 py-3 text-left text-xs font-medium ${isDark ? 'text-gray-400' : 'text-gray-700'} uppercase tracking-wider`}>
                  Threats
                </th>
                <th className={`px-6 py-3 text-left text-xs font-medium ${isDark ? 'text-gray-400' : 'text-gray-700'} uppercase tracking-wider`}>
                  Threat %
                </th>
                <th className={`px-6 py-3 text-left text-xs font-medium ${isDark ? 'text-gray-400' : 'text-gray-700'} uppercase tracking-wider`}>
                  Risk Level
                </th>
              </tr>
            </thead>
            <tbody className={`divide-y ${isDark ? 'divide-gray-700' : 'divide-gray-200'}`}>
              {effectiveIpData?.map((ip, idx) => (
                <tr key={idx} className={`${isDark ? 'hover:bg-gray-700/50' : 'hover:bg-gray-50'}`}>
                  <td className={`px-6 py-4 whitespace-nowrap text-sm font-mono font-medium ${isDark ? 'text-white' : 'text-gray-900'}`}>
                    {ip.ip}
                  </td>
                  <td className={`px-6 py-4 whitespace-nowrap text-sm ${isDark ? 'text-gray-300' : 'text-gray-900'}`}>
                    {ip.total}
                  </td>
                  <td className={`px-6 py-4 whitespace-nowrap text-sm ${isDark ? 'text-gray-300' : 'text-gray-900'}`}>
                    {ip.threats}
                  </td>
                  <td className={`px-6 py-4 whitespace-nowrap text-sm ${isDark ? 'text-gray-300' : 'text-gray-900'}`}>
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
        {(!effectiveIpData || effectiveIpData.length === 0) && (
          <div className={`text-center py-12 ${isDark ? 'text-gray-500' : 'text-gray-400'}`}>
            No IP data available - upload and analyze files to see IP risk analysis
          </div>
        )}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Feature Importance */}
        <div className={`${isDark ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} rounded-xl shadow-sm border p-6`}>
          <h2 className={`text-xl font-semibold ${isDark ? 'text-white' : 'text-gray-900'} mb-4`}>Feature Importance</h2>
          {effectiveFeatures && effectiveFeatures.length > 0 ? (
            <ResponsiveContainer width="100%" height={350}>
              <BarChart data={effectiveFeatures} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke={isDark ? '#374151' : '#e5e7eb'} />
                <XAxis type="number" domain={[0, 1]} tick={{ fill: isDark ? '#9ca3af' : '#374151' }} />
                <YAxis
                  dataKey="feature"
                  type="category"
                  width={120}
                  tick={{ fontSize: 12, fill: isDark ? '#9ca3af' : '#374151' }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: isDark ? '#1f2937' : '#fff',
                    border: `1px solid ${isDark ? '#374151' : '#e5e7eb'}`,
                    borderRadius: '8px',
                    color: isDark ? '#fff' : '#000'
                  }}
                  formatter={(value) => [`${(value * 100).toFixed(1)}%`, 'Importance']}
                />
                <Bar dataKey="importance" fill="#3b82f6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className={`h-[350px] flex items-center justify-center ${isDark ? 'text-gray-500' : 'text-gray-400'}`}>
              No feature data available - analyze files to see feature importance
            </div>
          )}
        </div>

        {/* Detection Methods */}
        <div className={`${isDark ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} rounded-xl shadow-sm border p-6`}>
          <h2 className={`text-xl font-semibold ${isDark ? 'text-white' : 'text-gray-900'} mb-4`}>Detection Method Breakdown</h2>
          {effectiveMethods && effectiveMethods.length > 0 ? (
            <ResponsiveContainer width="100%" height={350}>
              <PieChart>
                <Pie
                  data={effectiveMethods}
                  cx="50%"
                  cy="45%"
                  labelLine={true}
                  label={renderPieLabel}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="count"
                  nameKey="method"
                >
                  {effectiveMethods.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={METHOD_COLORS[entry.method] || '#6b7280'} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend
                  verticalAlign="bottom"
                  align="center"
                  wrapperStyle={{ paddingTop: '20px' }}
                  formatter={(value) => (
                    <span style={{ color: isDark ? '#e5e7eb' : '#374151', fontSize: '12px' }}>{value}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className={`h-[350px] flex items-center justify-center ${isDark ? 'text-gray-500' : 'text-gray-400'}`}>
              No detection data available - analyze files to see method breakdown
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Analysis;
