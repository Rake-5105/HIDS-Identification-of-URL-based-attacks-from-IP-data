import { useState, useMemo } from 'react';
import { Search, Filter, ChevronUp, ChevronDown, RefreshCw } from 'lucide-react';
import { useApi } from '../hooks/useApi';
import RequestDetail, { ATTACK_COLORS } from '../components/RequestDetail';
import { useTheme } from '../context/ThemeContext';

const Requests = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const { data: requests, loading, error, refetch } = useApi('/api/requests');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterClass, setFilterClass] = useState('all');
  const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });
  const [selectedRequest, setSelectedRequest] = useState(null);
  const [selectedIndex, setSelectedIndex] = useState(null);

  const classifications = useMemo(() => {
    if (!requests) return [];
    const unique = [...new Set(requests.map(r => r.classification))];
    return unique.filter(Boolean).sort();
  }, [requests]);

  const filteredAndSorted = useMemo(() => {
    if (!requests) return [];

    let filtered = requests.filter(req => {
      const matchesSearch = searchTerm === '' ||
        req.url?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        req.source_ip?.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesFilter = filterClass === 'all' ||
        req.classification?.toLowerCase() === filterClass.toLowerCase();

      return matchesSearch && matchesFilter;
    });

    if (sortConfig.key) {
      filtered.sort((a, b) => {
        const aVal = a[sortConfig.key];
        const bVal = b[sortConfig.key];

        if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1;
        return 0;
      });
    }

    return filtered;
  }, [requests, searchTerm, filterClass, sortConfig]);

  const handleSort = (key) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc'
    }));
  };

  const SortIcon = ({ column }) => {
    if (sortConfig.key !== column) return null;
    return sortConfig.direction === 'asc' ? <ChevronUp size={16} /> : <ChevronDown size={16} />;
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold text-gray-900">Requests</h1>
        <div className="skeleton h-96 rounded-xl" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold text-gray-900">Requests</h1>
        <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-center">
          <p className="text-red-800 mb-4">{error}</p>
          <button
            onClick={refetch}
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
        <h1 className="text-3xl font-bold text-gray-900">Requests</h1>
        <button
          onClick={refetch}
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

      {/* Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by IP or URL..."
              className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>

          {/* Filter */}
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <select
              value={filterClass}
              onChange={(e) => setFilterClass(e.target.value)}
              className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent appearance-none bg-white"
            >
              <option value="all">All Classifications</option>
              {classifications.map(cls => (
                <option key={cls} value={cls}>{cls.toUpperCase()}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="mt-4 text-sm text-gray-600">
          Showing {filteredAndSorted.length} of {requests.length} requests
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th
                  onClick={() => handleSort('timestamp')}
                  className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                >
                  <div className="flex items-center space-x-1">
                    <span>Timestamp</span>
                    <SortIcon column="timestamp" />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('source_ip')}
                  className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                >
                  <div className="flex items-center space-x-1">
                    <span>Source IP</span>
                    <SortIcon column="source_ip" />
                  </div>
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">
                  URL
                </th>
                <th
                  onClick={() => handleSort('classification')}
                  className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                >
                  <div className="flex items-center space-x-1">
                    <span>Classification</span>
                    <SortIcon column="classification" />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('confidence')}
                  className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                >
                  <div className="flex items-center space-x-1">
                    <span>Confidence</span>
                    <SortIcon column="confidence" />
                  </div>
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">
                  Method
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {filteredAndSorted.map((req, idx) => {
                const classification = req.classification?.toLowerCase() || 'unknown';
                const colors = ATTACK_COLORS[classification] || ATTACK_COLORS.unknown;

                return (
                  <tr
                    key={idx}
                    onClick={() => {
                      setSelectedRequest(req);
                      setSelectedIndex(idx);
                    }}
                    className="hover:bg-gray-50 cursor-pointer transition-colors"
                  >
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {req.timestamp ? new Date(req.timestamp).toLocaleString() : 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                      {req.source_ip || 'N/A'}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900 max-w-md truncate">
                      {req.url || 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-3 py-1 text-xs font-semibold rounded-full ${colors.bg} ${colors.text}`}>
                        {classification.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center space-x-2">
                        <div className="flex-1 h-2 bg-gray-200 rounded-full overflow-hidden max-w-[100px]">
                          <div
                            className="h-full bg-blue-600"
                            style={{ width: `${parseFloat(req.confidence || 0)}%` }}
                          />
                        </div>
                        <span className="text-sm text-gray-900">
                          {parseFloat(req.confidence || 0).toFixed(0)}%
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 capitalize">
                      {req.detection_method || 'N/A'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {filteredAndSorted.length === 0 && (
          <div className="text-center py-12 text-gray-400">
            No requests found matching your criteria
          </div>
        )}
      </div>

      {/* Detail Panel */}
      {selectedRequest && (
        <RequestDetail
          request={selectedRequest}
          index={selectedIndex}
          onClose={() => setSelectedRequest(null)}
        />
      )}
    </div>
  );
};

export default Requests;
