import { Activity, AlertTriangle, Target, Shield, RefreshCw } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import StatCard from '../components/StatCard';
import AttackPieChart from '../components/AttackPieChart';
import TimelineChart from '../components/TimelineChart';
import { useApi } from '../hooks/useApi';
import { ATTACK_COLORS } from '../components/RequestDetail';

const Dashboard = () => {
  const { data: summary, loading: summaryLoading, error: summaryError, refetch: refetchSummary } = useApi('/api/summary');
  const { data: requests, loading: requestsLoading } = useApi('/api/requests');
  const { data: timeline } = useApi('/api/analysis/timeline');
  const navigate = useNavigate();

  if (summaryLoading || requestsLoading) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className="skeleton h-32 rounded-xl" />
          ))}
        </div>
      </div>
    );
  }

  if (summaryError) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-center">
          <AlertTriangle className="w-12 h-12 text-red-600 mx-auto mb-4" />
          <p className="text-red-800 mb-4">{summaryError}</p>
          <button
            onClick={refetchSummary}
            className="inline-flex items-center space-x-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
          >
            <RefreshCw size={16} />
            <span>Retry</span>
          </button>
        </div>
      </div>
    );
  }

  const threatPercentage = summary?.total_requests > 0
    ? ((summary.threats_detected / summary.total_requests) * 100).toFixed(1)
    : 0;

  const recentThreats = requests
    ?.filter(r => r.classification?.toLowerCase() !== 'normal')
    .slice(0, 10) || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <button
          onClick={refetchSummary}
          className="inline-flex items-center space-x-2 px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
        >
          <RefreshCw size={16} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Requests"
          value={summary?.total_requests || 0}
          icon={Activity}
          color="blue"
        />
        <StatCard
          title="Threats Detected"
          value={summary?.threats_detected || 0}
          icon={AlertTriangle}
          color="red"
          badge={{
            text: `${threatPercentage}%`,
            color: parseFloat(threatPercentage) > 50 ? 'red' : 'green'
          }}
        />
        <StatCard
          title="ML Accuracy"
          value={`${((summary?.ml_accuracy || 0) * 100).toFixed(1)}%`}
          icon={Target}
          color="green"
        />
        <StatCard
          title="Suspicious IPs"
          value={summary?.suspicious_ips?.length || 0}
          icon={Shield}
          color="yellow"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <AttackPieChart data={summary?.class_counts} />
        <TimelineChart data={timeline} />
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Threats */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Threats</h3>
          {recentThreats.length === 0 ? (
            <p className="text-center text-gray-400 py-8">No threats detected</p>
          ) : (
            <div className="space-y-3">
              {recentThreats.map((threat, idx) => {
                const classification = threat.classification?.toLowerCase() || 'unknown';
                const colors = ATTACK_COLORS[classification] || ATTACK_COLORS.unknown;

                return (
                  <div
                    key={idx}
                    className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 cursor-pointer transition-colors"
                    onClick={() => navigate('/requests')}
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-2 mb-1">
                        <span className={`px-2 py-1 text-xs font-semibold rounded ${colors.bg} ${colors.text}`}>
                          {classification.toUpperCase()}
                        </span>
                        <span className="text-xs text-gray-500">{threat.source_ip}</span>
                      </div>
                      <p className="text-sm text-gray-700 truncate">{threat.url}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Suspicious IPs */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Suspicious IP Addresses</h3>
          {!summary?.suspicious_ips || summary.suspicious_ips.length === 0 ? (
            <p className="text-center text-gray-400 py-8">No suspicious IPs detected</p>
          ) : (
            <div className="space-y-2">
              {summary.suspicious_ips.map((ip, idx) => (
                <div
                  key={idx}
                  onClick={() => navigate('/analysis')}
                  className="px-4 py-3 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 cursor-pointer transition-colors"
                >
                  <p className="font-mono text-sm font-medium text-red-900">{ip}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
