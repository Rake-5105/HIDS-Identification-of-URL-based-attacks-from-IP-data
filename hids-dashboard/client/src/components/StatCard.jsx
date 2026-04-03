const StatCard = ({ title, value, icon: Icon, badge, color = 'blue' }) => {
  const colorClasses = {
    blue: 'bg-blue-50 text-blue-600',
    red: 'bg-red-50 text-red-600',
    green: 'bg-green-50 text-green-600',
    yellow: 'bg-yellow-50 text-yellow-600'
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-600 mb-2">{title}</p>
          <div className="flex items-baseline space-x-2">
            <h3 className="text-3xl font-bold text-gray-900">{value}</h3>
            {badge && (
              <span className={`px-2 py-1 text-xs font-semibold rounded-full ${
                badge.color === 'red'
                  ? 'bg-red-100 text-red-800'
                  : badge.color === 'green'
                  ? 'bg-green-100 text-green-800'
                  : 'bg-gray-100 text-gray-800'
              }`}>
                {badge.text}
              </span>
            )}
          </div>
        </div>
        {Icon && (
          <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
            <Icon size={24} />
          </div>
        )}
      </div>
    </div>
  );
};

export default StatCard;
