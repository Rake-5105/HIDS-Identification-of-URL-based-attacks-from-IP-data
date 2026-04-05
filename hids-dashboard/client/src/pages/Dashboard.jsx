import {
  Activity, AlertTriangle, Target, Shield, RefreshCw, FileUp,
  Clock, Zap, ChevronRight, X, History, Trash2, FileText,
  ShieldAlert, BarChart3, ArrowUpRight
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import StatCard from '../components/StatCard';
import AttackPieChart from '../components/AttackPieChart';
import TimelineChart from '../components/TimelineChart';
import { useApi } from '../hooks/useApi';
import { ATTACK_COLORS } from '../components/RequestDetail';
import { useUpload } from '../context/UploadContext';

/* ── tiny helper ── */
const classColor = (cls) => {
  const k = cls.toLowerCase();
  if (k === 'normal') return { dot: 'bg-emerald-500', badge: 'bg-emerald-100 text-emerald-800 border-emerald-200' };
  if (k.includes('sql')) return { dot: 'bg-red-500', badge: 'bg-red-100 text-red-800 border-red-200' };
  if (k.includes('xss')) return { dot: 'bg-orange-500', badge: 'bg-orange-100 text-orange-800 border-orange-200' };
  if (k.includes('path')) return { dot: 'bg-yellow-500', badge: 'bg-yellow-100 text-yellow-800 border-yellow-200' };
  if (k.includes('command')) return { dot: 'bg-purple-500', badge: 'bg-purple-100 text-purple-800 border-purple-200' };
  if (k.includes('ldap')) return { dot: 'bg-indigo-500', badge: 'bg-indigo-100 text-indigo-800 border-indigo-200' };
  if (k.includes('ssrf')) return { dot: 'bg-teal-500', badge: 'bg-teal-100 text-teal-800 border-teal-200' };
  if (k.includes('rfi') || k.includes('remote')) return { dot: 'bg-pink-500', badge: 'bg-pink-100 text-pink-800 border-pink-200' };
  if (k.includes('lfi') || k.includes('local')) return { dot: 'bg-amber-500', badge: 'bg-amber-100 text-amber-800 border-amber-200' };
  return { dot: 'bg-gray-500', badge: 'bg-gray-100 text-gray-800 border-gray-200' };
};

const timeAgo = (isoString) => {
  if (!isoString) return '';
  const diff = Date.now() - new Date(isoString).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
};

const Dashboard = () => {
  const { data: summary, loading: summaryLoading, error: summaryError, refetch: refetchSummary } = useApi('/api/summary');
  const { data: requests, loading: requestsLoading } = useApi('/api/requests');
  const { data: timeline } = useApi('/api/analysis/timeline');
  const { latestResult, resultsHistory, clearResult, clearHistory, removeFromHistory } = useUpload();
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

  /* ── aggregate stats from history ── */
  const totalHistoryScans = resultsHistory.length;
  const totalHistoryThreats = resultsHistory.reduce((sum, r) => sum + (r.threats_detected || 0), 0);
  const totalHistoryEntries = resultsHistory.reduce((sum, r) => sum + (r.total_requests || 0), 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <button
          onClick={refetchSummary}
          className="inline-flex items-center space-x-2 px-4 py-2 bg-gray-800 text-gray-200 border border-gray-600 rounded-lg hover:bg-gray-700 hover:text-white transition-colors shadow-sm"
        >
          <RefreshCw size={16} />
          <span>Refresh</span>
        </button>
      </div>

      {/* ═══  Latest Upload Results Banner ═══ */}
      {latestResult && (
        <div className="relative overflow-hidden rounded-2xl border border-blue-200 bg-gradient-to-r from-blue-50 via-indigo-50 to-purple-50 shadow-lg animate-slideDown">
          {/* Decorative accent */}
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 via-indigo-500 to-purple-500" />

          {/* Close button */}
          <button
            onClick={clearResult}
            className="absolute top-4 right-4 p-1.5 rounded-full bg-white/80 hover:bg-white text-gray-500 hover:text-gray-700 transition-colors shadow-sm z-10"
            title="Dismiss"
          >
            <X size={16} />
          </button>

          <div className="p-6">
            {/* Title row */}
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2.5 rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 shadow-md">
                <FileUp size={22} className="text-white" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-gray-900">Latest Analysis Result</h2>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="text-sm text-gray-600 font-medium">{latestResult.filename || 'Uploaded file'}</span>
                  {latestResult.analyzedAt && (
                    <span className="flex items-center gap-1 text-xs text-gray-400">
                      <Clock size={11} />
                      {new Date(latestResult.analyzedAt).toLocaleString()}
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Stats grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
              <div className="bg-white/80 backdrop-blur-sm rounded-xl p-4 border border-white shadow-sm">
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wider">Total Entries</p>
                <p className="text-2xl font-bold text-gray-900 mt-1">{latestResult.total_requests || 0}</p>
              </div>
              <div className="bg-white/80 backdrop-blur-sm rounded-xl p-4 border border-white shadow-sm">
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wider">Threats Found</p>
                <div className="flex items-baseline gap-2 mt-1">
                  <p className="text-2xl font-bold text-red-600">{latestResult.threats_detected || 0}</p>
                  {latestResult.threats_detected > 0 && (
                    <span className="px-1.5 py-0.5 text-[10px] font-bold rounded-full bg-red-100 text-red-700 animate-pulse">
                      ⚠ ALERT
                    </span>
                  )}
                </div>
              </div>
              <div className="bg-white/80 backdrop-blur-sm rounded-xl p-4 border border-white shadow-sm">
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wider">Threat Rate</p>
                <p className={`text-2xl font-bold mt-1 ${
                  (latestResult.threat_percentage || 0) > 50 ? 'text-red-600' :
                  (latestResult.threat_percentage || 0) > 20 ? 'text-orange-600' :
                  'text-emerald-600'
                }`}>
                  {latestResult.threat_percentage || 0}%
                </p>
              </div>
              <div className="bg-white/80 backdrop-blur-sm rounded-xl p-4 border border-white shadow-sm">
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wider">AI Model</p>
                <div className="flex items-center gap-1.5 mt-1">
                  <Zap size={16} className="text-blue-500" />
                  <p className="text-lg font-bold text-blue-600">{latestResult.analyzed_with || 'Phi3'}</p>
                </div>
              </div>
            </div>

            {/* Classification Breakdown */}
            {latestResult.classification_breakdown && Object.keys(latestResult.classification_breakdown).length > 0 && (
              <div className="bg-white/60 backdrop-blur-sm rounded-xl p-4 border border-white/80 mb-4">
                <p className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-3">Attack Classification Breakdown</p>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(latestResult.classification_breakdown).map(([cls, count]) => {
                    const colors = classColor(cls);
                    return (
                      <span
                        key={cls}
                        className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold transition-transform hover:scale-105 border ${colors.badge}`}
                      >
                        <span className={`w-2 h-2 rounded-full ${colors.dot}`} />
                        {cls}: {count}
                      </span>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center gap-3">
              <button
                onClick={() => navigate('/app/upload')}
                className="inline-flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-blue-600 to-indigo-600 text-white text-sm font-medium rounded-lg hover:from-blue-700 hover:to-indigo-700 transition-all shadow-sm hover:shadow-md"
              >
                View Full Results
                <ChevronRight size={16} />
              </button>
              <button
                onClick={clearResult}
                className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900 transition-colors"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}

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

      {/* ═══  Analysis History Section ═══ */}
      {resultsHistory.length > 0 && (
        <div className="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden">
          {/* Section header */}
          <div className="px-6 py-5 border-b border-gray-100 bg-gradient-to-r from-gray-50 to-white">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-gradient-to-br from-violet-500 to-purple-600 shadow-sm">
                  <History size={18} className="text-white" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-900">Analysis History</h2>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {totalHistoryScans} scan{totalHistoryScans !== 1 ? 's' : ''} • {totalHistoryEntries.toLocaleString()} total entries analyzed • {totalHistoryThreats.toLocaleString()} threats found
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => navigate('/app/upload')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-600 bg-blue-50 rounded-lg hover:bg-blue-100 transition-colors"
                >
                  <FileUp size={14} />
                  New Scan
                </button>
                {resultsHistory.length > 1 && (
                  <button
                    onClick={clearHistory}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-600 bg-red-50 rounded-lg hover:bg-red-100 transition-colors"
                    title="Clear all history"
                  >
                    <Trash2 size={14} />
                    Clear All
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* History table */}
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-gray-50/80">
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">File</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Analyzed</th>
                  <th className="px-6 py-3 text-center text-xs font-semibold text-gray-500 uppercase tracking-wider">Entries</th>
                  <th className="px-6 py-3 text-center text-xs font-semibold text-gray-500 uppercase tracking-wider">Threats</th>
                  <th className="px-6 py-3 text-center text-xs font-semibold text-gray-500 uppercase tracking-wider">Threat %</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Attacks Detected</th>
                  <th className="px-6 py-3 text-center text-xs font-semibold text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {resultsHistory.map((result, idx) => {
                  const isLatest = idx === 0;
                  const threatPct = result.threat_percentage || 0;
                  const threatLevel = threatPct > 50 ? 'high' : threatPct > 20 ? 'medium' : 'low';
                  const attackTypes = result.classification_breakdown
                    ? Object.entries(result.classification_breakdown).filter(([cls]) => cls.toLowerCase() !== 'normal')
                    : [];

                  return (
                    <tr
                      key={result.upload_id || idx}
                      className={`hover:bg-gray-50/80 transition-colors ${isLatest ? 'bg-blue-50/30' : ''}`}
                    >
                      {/* Filename */}
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <div className={`p-1.5 rounded-lg ${isLatest ? 'bg-blue-100' : 'bg-gray-100'}`}>
                            <FileText size={16} className={isLatest ? 'text-blue-600' : 'text-gray-500'} />
                          </div>
                          <div>
                            <p className="text-sm font-medium text-gray-900 truncate max-w-[200px]">
                              {result.filename || 'Unknown file'}
                            </p>
                            {isLatest && (
                              <span className="inline-flex items-center px-1.5 py-0.5 text-[10px] font-semibold rounded bg-blue-100 text-blue-700 mt-0.5">
                                LATEST
                              </span>
                            )}
                          </div>
                        </div>
                      </td>

                      {/* Time */}
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-1.5 text-sm text-gray-600">
                          <Clock size={13} className="text-gray-400" />
                          <span title={result.analyzedAt ? new Date(result.analyzedAt).toLocaleString() : ''}>
                            {timeAgo(result.analyzedAt)}
                          </span>
                        </div>
                      </td>

                      {/* Total entries */}
                      <td className="px-6 py-4 text-center">
                        <span className="text-sm font-semibold text-gray-900">
                          {(result.total_requests || 0).toLocaleString()}
                        </span>
                      </td>

                      {/* Threats */}
                      <td className="px-6 py-4 text-center">
                        <span className={`inline-flex items-center justify-center min-w-[2rem] px-2 py-0.5 text-sm font-bold rounded-full ${
                          (result.threats_detected || 0) > 0
                            ? 'bg-red-100 text-red-700'
                            : 'bg-emerald-100 text-emerald-700'
                        }`}>
                          {result.threats_detected || 0}
                        </span>
                      </td>

                      {/* Threat % */}
                      <td className="px-6 py-4 text-center">
                        <div className="flex flex-col items-center gap-1">
                          <span className={`text-sm font-bold ${
                            threatLevel === 'high' ? 'text-red-600' :
                            threatLevel === 'medium' ? 'text-orange-600' :
                            'text-emerald-600'
                          }`}>
                            {threatPct}%
                          </span>
                          <div className="w-16 h-1.5 bg-gray-200 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all ${
                                threatLevel === 'high' ? 'bg-red-500' :
                                threatLevel === 'medium' ? 'bg-orange-500' :
                                'bg-emerald-500'
                              }`}
                              style={{ width: `${Math.min(threatPct, 100)}%` }}
                            />
                          </div>
                        </div>
                      </td>

                      {/* Attacks Detected */}
                      <td className="px-6 py-4">
                        {attackTypes.length > 0 ? (
                          <div className="flex flex-wrap gap-1 max-w-[250px]">
                            {attackTypes.slice(0, 4).map(([cls, count]) => {
                              const colors = classColor(cls);
                              return (
                                <span
                                  key={cls}
                                  className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${colors.badge}`}
                                >
                                  <span className={`w-1.5 h-1.5 rounded-full ${colors.dot}`} />
                                  {cls}: {count}
                                </span>
                              );
                            })}
                            {attackTypes.length > 4 && (
                              <span className="px-2 py-0.5 text-[11px] font-medium text-gray-500 bg-gray-100 rounded-full">
                                +{attackTypes.length - 4} more
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                            Clean
                          </span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="px-6 py-4 text-center">
                        <div className="flex items-center justify-center gap-1">
                          <button
                            onClick={() => navigate('/app/upload')}
                            className="p-1.5 rounded-lg text-blue-600 hover:bg-blue-50 transition-colors"
                            title="View details"
                          >
                            <ArrowUpRight size={16} />
                          </button>
                          <button
                            onClick={() => removeFromHistory(result.upload_id)}
                            className="p-1.5 rounded-lg text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors"
                            title="Remove from history"
                          >
                            <X size={16} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Summary bar */}
          <div className="px-6 py-3 bg-gray-50/80 border-t border-gray-100">
            <div className="flex items-center justify-between">
              <p className="text-xs text-gray-500">
                Showing {resultsHistory.length} analysis result{resultsHistory.length !== 1 ? 's' : ''}
              </p>
              <div className="flex items-center gap-4 text-xs text-gray-500">
                <span className="flex items-center gap-1">
                  <BarChart3 size={12} />
                  Avg threat rate: {totalHistoryEntries > 0
                    ? ((totalHistoryThreats / totalHistoryEntries) * 100).toFixed(1)
                    : '0'
                  }%
                </span>
                <span className="flex items-center gap-1">
                  <ShieldAlert size={12} />
                  Total threats: {totalHistoryThreats.toLocaleString()}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

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
                    onClick={() => navigate('/app/requests')}
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
                  onClick={() => navigate('/app/analysis')}
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
