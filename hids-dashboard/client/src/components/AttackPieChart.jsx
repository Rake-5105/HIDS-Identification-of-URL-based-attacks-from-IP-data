import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';

const ATTACK_COLORS = {
  normal: '#22c55e',
  sqli: '#ef4444',
  xss: '#f97316',
  path_traversal: '#eab308',
  cmdi: '#a855f7',
  unknown: '#6b7280'
};

const AttackPieChart = ({ data }) => {
  if (!data) return null;

  const chartData = Object.entries(data).map(([name, value]) => ({
    name: name.replace('_', ' ').toUpperCase(),
    value,
    color: ATTACK_COLORS[name] || ATTACK_COLORS.unknown
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
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Attack Type Distribution</h3>
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
              <span className="text-sm text-gray-700">{value} ({entry.payload.value})</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};

export default AttackPieChart;
