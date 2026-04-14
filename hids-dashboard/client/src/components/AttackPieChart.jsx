import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';

const ATTACK_COLORS = {
  normal: '#10b981',
  sql_injection: '#ef4444',
  cross_site_scripting_xss: '#f97316',
  directory_traversal: '#eab308',
  command_injection: '#8b5cf6',
  phishing: '#06b6d4',
  suspicious: '#06b6d4',
  suspicious_behavior: '#06b6d4',
  unknown: '#64748b'
};

const ATTACK_ALIASES = {
  sqli: 'sql_injection',
  sql: 'sql_injection',
  path_traversal: 'directory_traversal',
  traversal: 'directory_traversal',
  xss: 'cross_site_scripting_xss',
  cmdi: 'command_injection',
  command_injection: 'command_injection',
  phising: 'phishing',
  suspicious_behavior: 'suspicious_behavior'
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
  return ATTACK_COLORS[normalized] || ATTACK_COLORS.unknown;
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
      <ResponsiveContainer width="100%" height={320}>
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="45%"
            labelLine={false}
            label={renderCustomLabel}
            outerRadius={90}
            innerRadius={0}
            fill="#8884d8"
            dataKey="value"
            paddingAngle={1}
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} stroke={entry.color} />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
          <Legend
            verticalAlign="bottom"
            align="center"
            wrapperStyle={{ paddingTop: '20px' }}
            formatter={(value, entry) => (
              <span className="text-xs text-gray-700 dark:text-gray-300">
                {value} ({entry.payload.value.toLocaleString()})
              </span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};

export default AttackPieChart;
