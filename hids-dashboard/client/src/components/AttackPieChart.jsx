import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const ATTACK_COLORS = {
  normal: '#10b981',
  sql_injection: '#ef4444',
  cross_site_scripting_xss: '#f97316',
  directory_traversal: '#eab308',
  command_injection: '#8b5cf6',
  phishing: '#06b6d4',
  suspicious: '#14b8a6',
  suspicious_behavior: '#0ea5e9',
  ldap_injection: '#6366f1',
  ssrf: '#22c55e',
  remote_file_inclusion_rfi: '#ec4899',
  local_file_inclusion_lfi: '#f59e0b',
  typosquatting_url_spoofing: '#d946ef',
  web_shell_upload: '#e11d48',
  denial_of_service_dos: '#f43f5e',
  http_header_injection: '#38bdf8',
  cross_site_request_forgery_csrf: '#84cc16',
  xml_external_entity_injection_xxe: '#fb7185',
  brute_force_credential_stuffing: '#64748b',
  unknown: '#64748b'
};

const FALLBACK_COLORS = [
  '#06b6d4', '#a855f7', '#22c55e', '#f59e0b', '#f43f5e',
  '#14b8a6', '#3b82f6', '#ef4444', '#8b5cf6', '#84cc16',
  '#0ea5e9', '#d946ef', '#eab308', '#ec4899', '#6366f1'
];

const ATTACK_ALIASES = {
  sqli: 'sql_injection',
  sql: 'sql_injection',
  path_traversal: 'directory_traversal',
  traversal: 'directory_traversal',
  xss: 'cross_site_scripting_xss',
  cmdi: 'command_injection',
  command_injection: 'command_injection',
  phising: 'phishing',
  suspicious_behavior: 'suspicious_behavior',
  ldap: 'ldap_injection',
  ldapi: 'ldap_injection',
  rfi: 'remote_file_inclusion_rfi',
  lfi: 'local_file_inclusion_lfi',
  dos: 'denial_of_service_dos',
  csrf: 'cross_site_request_forgery_csrf',
  xxe: 'xml_external_entity_injection_xxe'
};

const normalizeAttackKey = (name) => {
  const cleaned = String(name || '')
    .toLowerCase()
    .replace(/[()]/g, '')
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');

  return ATTACK_ALIASES[cleaned] || cleaned;
};

const getAttackColor = (name) => {
  const normalized = normalizeAttackKey(name);
  if (ATTACK_COLORS[normalized]) {
    return ATTACK_COLORS[normalized];
  }

  // Deterministic fallback: same unknown class always gets same color.
  const hash = normalized.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
  return FALLBACK_COLORS[hash % FALLBACK_COLORS.length] || ATTACK_COLORS.unknown;
};

const formatAttackName = (name) => {
  return String(name || '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
};

const AttackPieChart = ({ data }) => {
  if (!data || Object.keys(data).length === 0) return null;

  // Sort by value descending and prepare chart data
  const chartData = Object.entries(data)
    .map(([name, value]) => ({
      name: formatAttackName(name),
      value: Number(value) || 0,
      color: getAttackColor(name)
    }))
    .filter(item => item.value > 0)
    .sort((a, b) => b.value - a.value);

  if (chartData.length === 0) return null;

  const total = chartData.reduce((sum, item) => sum + item.value, 0);

  // Custom label - only show for slices > 5% to avoid crowding
  const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, value, percent }) => {
    if (percent < 0.05) return null; // Don't label tiny slices
    
    const RADIAN = Math.PI / 180;
    const radius = innerRadius + (outerRadius - innerRadius) * 0.6;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);

    return (
      <text
        x={x}
        y={y}
        fill="white"
        textAnchor="middle"
        dominantBaseline="central"
        style={{ fontSize: '12px', fontWeight: 'bold', textShadow: '1px 1px 2px rgba(0,0,0,0.5)' }}
      >
        {value.toLocaleString()}
      </text>
    );
  };

  // Custom tooltip
  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const item = payload[0].payload;
      const percentage = ((item.value / total) * 100).toFixed(1);
      return (
        <div className="bg-gray-900 text-white px-3 py-2 rounded-lg shadow-lg text-sm">
          <p className="font-semibold">{item.name}</p>
          <p>{item.value.toLocaleString()} ({percentage}%)</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6 bg-white dark:bg-gray-800">
      <h3 className="text-lg font-semibold text-indigo-900 dark:text-white mb-4">Attack Type Distribution</h3>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-start">
        {/* Keep chart square so the pie never stretches out of shape */}
        <div className="w-full max-w-[360px] mx-auto">
          <ResponsiveContainer width="100%" aspect={1}>
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={renderCustomLabel}
                outerRadius="82%"
                innerRadius="0%"
                fill="#8884d8"
                dataKey="value"
                paddingAngle={1}
              >
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} stroke={entry.color} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="space-y-2 max-h-[320px] overflow-y-auto pr-1">
          {chartData.map((item) => {
            const percentage = total > 0 ? ((item.value / total) * 100).toFixed(1) : '0.0';
            return (
              <div
                key={item.name}
                className="flex items-center justify-between gap-3 rounded-lg border border-gray-200 dark:border-gray-700 px-3 py-2"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-xs text-gray-700 dark:text-gray-300 truncate">{item.name}</span>
                </div>
                <div className="text-right flex-shrink-0">
                  <p className="text-xs font-semibold text-gray-900 dark:text-white">{item.value.toLocaleString()}</p>
                  <p className="text-[11px] text-gray-500">{percentage}%</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default AttackPieChart;
