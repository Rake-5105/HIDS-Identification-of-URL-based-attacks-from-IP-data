import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';

const ATTACK_COLORS = {
  normal: '#10b981',
  sql_injection: '#ef4444',
  cross_site_scripting_xss: '#f97316',
  directory_traversal: '#eab308',
  command_injection: '#8b5cf6',
  suspicious: '#06b6d4',
  unknown: '#64748b'
};

const ATTACK_ALIASES = {
  sqli: 'sql_injection',
  sql: 'sql_injection',
  path_traversal: 'directory_traversal',
  traversal: 'directory_traversal',
  xss: 'cross_site_scripting_xss',
  cmdi: 'command_injection',
  command_injection: 'command_injection'
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

const AttackPieChart = ({ data }) => {
  if (!data) return null;

  const chartData = Object.entries(data).map(([name, value]) => ({
    name: name.replace('_', ' ').toUpperCase(),
    value,
    color: getAttackColor(name)
  }));

  const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, value, name }) => {
    const RADIAN = Math.PI / 180;
    const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);

    return (
      <text
        x={x}
        y={y}
        fill="white"
        textAnchor={x > cx ? 'start' : 'end'}
        dominantBaseline="central"
        className="text-sm font-semibold"
      >
        {value}
      </text>
    );
  };

  return (
    <div className="rounded-xl shadow-sm border border-gray-200 p-6 bg-white">
      <h3 className="text-lg font-semibold text-indigo-900 mb-4">Attack Type Distribution</h3>
      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={renderCustomLabel}
            outerRadius={100}
            fill="#8884d8"
            dataKey="value"
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip />
          <Legend
            verticalAlign="bottom"
            height={36}
            formatter={(value, entry) => (
              <span className="text-sm text-indigo-800">{value} ({entry.payload.value})</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};

export default AttackPieChart;
