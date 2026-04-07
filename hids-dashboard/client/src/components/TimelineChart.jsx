import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const TimelineChart = ({ data }) => {
  if (!data || data.length === 0) {
    return (
      <div className="rounded-xl shadow-sm border border-gray-200 p-6 bg-white">
        <h3 className="text-lg font-semibold text-emerald-900 mb-4">Threat Timeline</h3>
        <div className="h-64 flex items-center justify-center text-gray-400">
          No timeline data available
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl shadow-sm border border-gray-200 p-6 bg-white">
      <h3 className="text-lg font-semibold text-emerald-900 mb-4">Threat Timeline</h3>
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.75}/>
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0.05}/>
            </linearGradient>
            <linearGradient id="colorNormal" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#10b981" stopOpacity={0.75}/>
              <stop offset="95%" stopColor="#10b981" stopOpacity={0.05}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis
            dataKey="timestamp"
            tick={{ fontSize: 12 }}
            angle={-45}
            textAnchor="end"
            height={80}
          />
          <YAxis />
          <Tooltip />
          <Legend />
          <Area
            type="monotone"
            dataKey="threats"
            stroke="#ef4444"
            strokeWidth={2.5}
            fillOpacity={1}
            fill="url(#colorThreats)"
            name="Threats"
          />
          <Area
            type="monotone"
            dataKey="normal"
            stroke="#10b981"
            strokeWidth={2.5}
            fillOpacity={1}
            fill="url(#colorNormal)"
            name="Normal"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

export default TimelineChart;
