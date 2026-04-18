import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, FileText, BarChart3, Upload, LogOut, Menu, X, Shield, Settings, Bot, PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

const Sidebar = ({ collapsed, setCollapsed }) => {
  const location = useLocation();
  const { user, logout } = useAuth();
  const [isCollapsedLogoHovered, setIsCollapsedLogoHovered] = useState(false);

  const menuItems = [
    { name: 'Dashboard', path: '/app/dashboard', icon: LayoutDashboard },
    { name: 'Requests', path: '/app/requests', icon: FileText },
    { name: 'Analysis', path: '/app/analysis', icon: BarChart3 },
    { name: 'Upload', path: '/app/upload', icon: Upload },
    { name: 'AI Assistant', path: '/app/ai', icon: Bot },
    { name: 'Profile', path: '/app/profile', icon: Settings }
  ];

  const isActive = (path) => location.pathname === path;

  return (
    <>
      {/* Mobile menu button */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="lg:hidden fixed top-4 left-4 z-50 p-2 bg-gray-900 text-white rounded-lg"
      >
        {collapsed ? <Menu size={24} /> : <X size={24} />}
      </button>

      {/* Sidebar */}
      <div
        className={`fixed top-0 left-0 h-full bg-gray-900 text-white transition-all duration-500 ease-in-out z-40 ${
          collapsed ? '-translate-x-full lg:translate-x-0 lg:w-20' : 'translate-x-0 w-64'
        }`}
      >
        {/* Logo */}
        <div className="p-4 border-b border-gray-800">
          <div className={`flex h-10 items-center ${collapsed ? 'justify-center' : 'justify-between'} gap-3`}>
            {collapsed ? (
              <button
                type="button"
                onClick={() => setCollapsed(false)}
                onMouseEnter={() => setIsCollapsedLogoHovered(true)}
                onMouseLeave={() => setIsCollapsedLogoHovered(false)}
                className="inline-flex h-10 w-10 items-center justify-center rounded-lg transition-all duration-300 hover:bg-gray-800 text-gray-300 hover:text-white"
                title="Expand sidebar"
              >
                {isCollapsedLogoHovered ? (
                  <PanelLeftOpen size={28} className="text-blue-400 flex-shrink-0" />
                ) : (
                  <Shield className="w-8 h-8 text-blue-500 flex-shrink-0" />
                )}
              </button>
            ) : (
              <Shield className="w-8 h-8 text-blue-500 flex-shrink-0" />
            )}

            {!collapsed && (
              <>
                <h1 className="flex-1 text-base font-bold leading-none whitespace-nowrap">HIDS Dashboard</h1>
                <button
                  onClick={() => setCollapsed(true)}
                  className="hidden lg:inline-flex h-10 w-10 items-center justify-center rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors duration-300"
                  title="Collapse sidebar"
                >
                  <PanelLeftClose size={18} />
                </button>
              </>
            )}
          </div>
        </div>

        {/* Menu items */}
        <nav className="p-4 space-y-2">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.path);

            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors ${
                  active
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                }`}
              >
                <Icon size={20} />
                {!collapsed && <span>{item.name}</span>}
              </Link>
            );
          })}
        </nav>

        {/* User section */}
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-gray-800">
          <Link
            to="/app/profile"
            className={`flex items-center ${collapsed ? 'justify-center' : 'justify-between'} hover:bg-gray-800 rounded-lg p-2 transition-colors`}
          >
            {!collapsed && (
              <div className="flex items-center gap-3 flex-1 min-w-0">
                <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-sm font-bold">
                  {user?.username?.charAt(0).toUpperCase() || 'U'}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{user?.username}</p>
                  <p className="text-xs text-gray-400 truncate">User</p>
                </div>
              </div>
            )}
            {collapsed && (
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-sm font-bold">
                {user?.username?.charAt(0).toUpperCase() || 'U'}
              </div>
            )}
          </Link>
          <button
            onClick={logout}
            className={`w-full mt-2 flex items-center ${collapsed ? 'justify-center' : 'gap-3'} p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg transition-colors`}
            title="Logout"
          >
            <LogOut size={20} />
            {!collapsed && <span>Logout</span>}
          </button>
        </div>
      </div>
    </>
  );
};

export default Sidebar;
