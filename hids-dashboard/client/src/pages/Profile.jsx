import { useState, useEffect, useContext } from 'react';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { useNavigate } from 'react-router-dom';

const Profile = () => {
  const { user, logout } = useContext(AuthContext);
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState('profile');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });

  // Profile data
  const [profile, setProfile] = useState(null);
  const [username, setUsername] = useState('');

  // Password change
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  // File history
  const [files, setFiles] = useState([]);
  const [filesPagination, setFilesPagination] = useState({ current: 1, pages: 1, total: 0 });

  // Stats
  const [stats, setStats] = useState(null);

  // Delete account
  const [deletePassword, setDeletePassword] = useState('');
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  useEffect(() => {
    fetchProfile();
    fetchStats();
  }, []);

  useEffect(() => {
    if (activeTab === 'history') {
      fetchFiles();
    }
  }, [activeTab]);

  const fetchProfile = async () => {
    try {
      const response = await axios.get('/api/profile');
      setProfile(response.data);
      setUsername(response.data.username);
    } catch (error) {
      showMessage('error', 'Failed to load profile');
    }
  };

  const fetchStats = async () => {
    try {
      const response = await axios.get('/api/profile/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  };

  const fetchFiles = async (page = 1) => {
    try {
      const response = await axios.get(`/api/profile/files?page=${page}&limit=10`);
      setFiles(response.data.files);
      setFilesPagination(response.data.pagination);
    } catch (error) {
      showMessage('error', 'Failed to load file history');
    }
  };

  const showMessage = (type, text) => {
    setMessage({ type, text });
    setTimeout(() => setMessage({ type: '', text: '' }), 5000);
  };

  const handleUpdateUsername = async (e) => {
    e.preventDefault();
    if (username.trim().length < 3) {
      showMessage('error', 'Username must be at least 3 characters');
      return;
    }

    setLoading(true);
    try {
      await axios.put('/api/profile/username', { username: username.trim() });
      showMessage('success', 'Username updated successfully');
      fetchProfile();
    } catch (error) {
      showMessage('error', error.response?.data?.message || 'Failed to update username');
    } finally {
      setLoading(false);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    
    if (newPassword.length < 6) {
      showMessage('error', 'New password must be at least 6 characters');
      return;
    }

    if (newPassword !== confirmPassword) {
      showMessage('error', 'Passwords do not match');
      return;
    }

    setLoading(true);
    try {
      await axios.put('/api/profile/password', { currentPassword, newPassword });
      showMessage('success', 'Password changed successfully');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (error) {
      showMessage('error', error.response?.data?.message || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteAccount = async () => {
    if (!deletePassword) {
      showMessage('error', 'Please enter your password to confirm');
      return;
    }

    setLoading(true);
    try {
      await axios.delete('/api/profile', { data: { password: deletePassword } });
      logout();
      navigate('/');
    } catch (error) {
      showMessage('error', error.response?.data?.message || 'Failed to delete account');
    } finally {
      setLoading(false);
      setShowDeleteConfirm(false);
      setDeletePassword('');
    }
  };

  const formatDate = (dateStr) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const tabs = [
    { id: 'profile', label: 'Profile', icon: '👤' },
    { id: 'security', label: 'Security', icon: '🔒' },
    { id: 'appearance', label: 'Appearance', icon: '🎨' },
    { id: 'history', label: 'File History', icon: '📁' },
    { id: 'reports', label: 'Reports', icon: '📊' },
  ];

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">User Settings</h1>
          <p className="text-gray-400">Manage your account settings and preferences</p>
        </div>

        {/* Message */}
        {message.text && (
          <div className={`mb-6 p-4 rounded-lg ${
            message.type === 'error' ? 'bg-red-500/20 text-red-400 border border-red-500/50' :
            'bg-green-500/20 text-green-400 border border-green-500/50'
          }`}>
            {message.text}
          </div>
        )}

        <div className="flex flex-col lg:flex-row gap-6">
          {/* Sidebar */}
          <div className="lg:w-64 flex-shrink-0">
            <div className="bg-gray-800 rounded-lg p-4">
              {/* User Info */}
              <div className="flex items-center gap-3 pb-4 border-b border-gray-700 mb-4">
                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-xl font-bold">
                  {profile?.username?.charAt(0).toUpperCase() || 'U'}
                </div>
                <div>
                  <div className="font-semibold">{profile?.username}</div>
                  <div className="text-sm text-gray-400">User</div>
                </div>
              </div>

              {/* Navigation */}
              <nav className="space-y-1">
                {tabs.map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                      activeTab === tab.id
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-400 hover:bg-gray-700 hover:text-white'
                    }`}
                  >
                    <span>{tab.icon}</span>
                    <span>{tab.label}</span>
                  </button>
                ))}
              </nav>
            </div>
          </div>

          {/* Main Content */}
          <div className="flex-1">
            <div className="bg-gray-800 rounded-lg p-6">
              {/* Profile Tab */}
              {activeTab === 'profile' && (
                <div>
                  <h2 className="text-xl font-semibold mb-6">Profile Information</h2>
                  
                  <form onSubmit={handleUpdateUsername} className="space-y-4 max-w-md">
                    <div>
                      <label className="block text-sm text-gray-400 mb-2">Username</label>
                      <input
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:border-blue-500"
                        minLength={3}
                      />
                    </div>

                    <div>
                      <label className="block text-sm text-gray-400 mb-2">Email</label>
                      <input
                        type="email"
                        value={profile?.email || ''}
                        disabled
                        className="w-full px-4 py-2 bg-gray-700/50 border border-gray-600 rounded-lg text-gray-400 cursor-not-allowed"
                      />
                      <p className="text-xs text-gray-500 mt-1">Email cannot be changed</p>
                    </div>

                    <div>
                      <label className="block text-sm text-gray-400 mb-2">Role</label>
                      <input
                        type="text"
                        value="User"
                        disabled
                        className="w-full px-4 py-2 bg-gray-700/50 border border-gray-600 rounded-lg text-gray-400 cursor-not-allowed"
                      />
                    </div>

                    <div>
                      <label className="block text-sm text-gray-400 mb-2">Member Since</label>
                      <input
                        type="text"
                        value={profile?.createdAt ? formatDate(profile.createdAt) : ''}
                        disabled
                        className="w-full px-4 py-2 bg-gray-700/50 border border-gray-600 rounded-lg text-gray-400 cursor-not-allowed"
                      />
                    </div>

                    <button
                      type="submit"
                      disabled={loading}
                      className="px-6 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg font-medium transition-colors disabled:opacity-50"
                    >
                      {loading ? 'Saving...' : 'Save Changes'}
                    </button>
                  </form>
                </div>
              )}

              {/* Security Tab */}
              {activeTab === 'security' && (
                <div>
                  <h2 className="text-xl font-semibold mb-6">Security Settings</h2>

                  {/* Change Password */}
                  <div className="mb-8">
                    <h3 className="text-lg font-medium mb-4">Change Password</h3>
                    <form onSubmit={handleChangePassword} className="space-y-4 max-w-md">
                      <div>
                        <label className="block text-sm text-gray-400 mb-2">Current Password</label>
                        <input
                          type="password"
                          value={currentPassword}
                          onChange={(e) => setCurrentPassword(e.target.value)}
                          className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:border-blue-500"
                          required
                        />
                      </div>

                      <div>
                        <label className="block text-sm text-gray-400 mb-2">New Password</label>
                        <input
                          type="password"
                          value={newPassword}
                          onChange={(e) => setNewPassword(e.target.value)}
                          className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:border-blue-500"
                          minLength={6}
                          required
                        />
                      </div>

                      <div>
                        <label className="block text-sm text-gray-400 mb-2">Confirm New Password</label>
                        <input
                          type="password"
                          value={confirmPassword}
                          onChange={(e) => setConfirmPassword(e.target.value)}
                          className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:border-blue-500"
                          minLength={6}
                          required
                        />
                      </div>

                      <button
                        type="submit"
                        disabled={loading}
                        className="px-6 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg font-medium transition-colors disabled:opacity-50"
                      >
                        {loading ? 'Changing...' : 'Change Password'}
                      </button>
                    </form>
                  </div>

                  {/* Delete Account */}
                  <div className="pt-6 border-t border-gray-700">
                    <h3 className="text-lg font-medium mb-2 text-red-400">Danger Zone</h3>
                    <p className="text-gray-400 text-sm mb-4">
                      Once you delete your account, there is no going back. Please be certain.
                    </p>

                    {!showDeleteConfirm ? (
                      <button
                        onClick={() => setShowDeleteConfirm(true)}
                        className="px-6 py-2 bg-red-600 hover:bg-red-700 rounded-lg font-medium transition-colors"
                      >
                        Delete Account
                      </button>
                    ) : (
                      <div className="max-w-md space-y-4 p-4 bg-red-500/10 border border-red-500/50 rounded-lg">
                        <p className="text-sm text-red-400">
                          Enter your password to confirm account deletion:
                        </p>
                        <input
                          type="password"
                          value={deletePassword}
                          onChange={(e) => setDeletePassword(e.target.value)}
                          placeholder="Your password"
                          className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:border-red-500"
                        />
                        <div className="flex gap-3">
                          <button
                            onClick={handleDeleteAccount}
                            disabled={loading}
                            className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg font-medium transition-colors disabled:opacity-50"
                          >
                            {loading ? 'Deleting...' : 'Confirm Delete'}
                          </button>
                          <button
                            onClick={() => {
                              setShowDeleteConfirm(false);
                              setDeletePassword('');
                            }}
                            className="px-4 py-2 bg-gray-600 hover:bg-gray-700 rounded-lg font-medium transition-colors"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Appearance Tab */}
              {activeTab === 'appearance' && (
                <div>
                  <h2 className="text-xl font-semibold mb-6">Appearance Settings</h2>
                  
                  <div className="max-w-md">
                    <h3 className="text-lg font-medium mb-4">Theme</h3>
                    <div className="grid grid-cols-2 gap-4">
                      <button
                        onClick={() => { if (theme !== 'dark') toggleTheme(); }}
                        className={`p-4 rounded-lg border-2 transition-all ${
                          theme === 'dark'
                            ? 'border-blue-500 bg-gray-700'
                            : 'border-gray-600 bg-gray-700/50 hover:border-gray-500'
                        }`}
                      >
                        <div className="w-full h-24 bg-gray-900 rounded-md mb-3 flex items-center justify-center">
                          <span className="text-3xl">🌙</span>
                        </div>
                        <div className="font-medium">Dark Mode</div>
                        <div className="text-sm text-gray-400">Easy on the eyes</div>
                        {theme === 'dark' && (
                          <div className="mt-2 text-xs text-blue-400">✓ Active</div>
                        )}
                      </button>

                      <button
                        onClick={() => { if (theme !== 'light') toggleTheme(); }}
                        className={`p-4 rounded-lg border-2 transition-all ${
                          theme === 'light'
                            ? 'border-blue-500 bg-gray-700'
                            : 'border-gray-600 bg-gray-700/50 hover:border-gray-500'
                        }`}
                      >
                        <div className="w-full h-24 bg-gray-200 rounded-md mb-3 flex items-center justify-center">
                          <span className="text-3xl">☀️</span>
                        </div>
                        <div className="font-medium">Light Mode</div>
                        <div className="text-sm text-gray-400">Classic bright theme</div>
                        {theme === 'light' && (
                          <div className="mt-2 text-xs text-blue-400">✓ Active</div>
                        )}
                      </button>
                    </div>
                    
                    <p className="text-gray-400 text-sm mt-4">
                      Current theme: <span className="text-white capitalize">{theme}</span>
                    </p>
                  </div>
                </div>
              )}

              {/* File History Tab */}
              {activeTab === 'history' && (
                <div>
                  <h2 className="text-xl font-semibold mb-6">File Upload History</h2>

                  {files.length === 0 ? (
                    <div className="text-center py-12 text-gray-400">
                      <div className="text-5xl mb-4">📁</div>
                      <p className="text-lg">No files uploaded yet</p>
                      <p className="text-sm">Upload a PCAP or log file to analyze network traffic</p>
                    </div>
                  ) : (
                    <>
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead>
                            <tr className="text-left text-gray-400 border-b border-gray-700">
                              <th className="pb-3 font-medium">File Name</th>
                              <th className="pb-3 font-medium">Type</th>
                              <th className="pb-3 font-medium">Status</th>
                              <th className="pb-3 font-medium">Threats</th>
                              <th className="pb-3 font-medium">Uploaded</th>
                            </tr>
                          </thead>
                          <tbody>
                            {files.map((file) => (
                              <tr key={file._id} className="border-b border-gray-700/50">
                                <td className="py-3">
                                  <div className="font-medium">{file.fileName}</div>
                                  <div className="text-sm text-gray-400">
                                    {(file.fileSize / 1024).toFixed(1)} KB
                                  </div>
                                </td>
                                <td className="py-3">
                                  <span className="px-2 py-1 bg-gray-700 rounded text-sm uppercase">
                                    {file.fileType}
                                  </span>
                                </td>
                                <td className="py-3">
                                  <span className={`px-2 py-1 rounded text-sm ${
                                    file.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                                    file.status === 'processing' ? 'bg-yellow-500/20 text-yellow-400' :
                                    file.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                                    'bg-gray-500/20 text-gray-400'
                                  }`}>
                                    {file.status}
                                  </span>
                                </td>
                                <td className="py-3">
                                  {file.results?.maliciousRequests > 0 ? (
                                    <span className="text-red-400">{file.results.maliciousRequests}</span>
                                  ) : (
                                    <span className="text-gray-400">0</span>
                                  )}
                                </td>
                                <td className="py-3 text-gray-400">
                                  {formatDate(file.uploadedAt)}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>

                      {/* Pagination */}
                      {filesPagination.pages > 1 && (
                        <div className="flex justify-center gap-2 mt-6">
                          {Array.from({ length: filesPagination.pages }, (_, i) => i + 1).map(page => (
                            <button
                              key={page}
                              onClick={() => fetchFiles(page)}
                              className={`px-3 py-1 rounded ${
                                page === filesPagination.current
                                  ? 'bg-blue-600 text-white'
                                  : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
                              }`}
                            >
                              {page}
                            </button>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}

              {/* Reports Tab */}
              {activeTab === 'reports' && (
                <div>
                  <h2 className="text-xl font-semibold mb-6">Activity Reports</h2>

                  {!stats ? (
                    <div className="text-center py-12 text-gray-400">
                      <div className="text-5xl mb-4">📊</div>
                      <p>Loading statistics...</p>
                    </div>
                  ) : (
                    <div className="space-y-6">
                      {/* Summary Stats */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div className="bg-gray-700 rounded-lg p-4">
                          <div className="text-3xl font-bold text-blue-400">{stats.totalFiles}</div>
                          <div className="text-gray-400 text-sm">Files Analyzed</div>
                        </div>
                        <div className="bg-gray-700 rounded-lg p-4">
                          <div className="text-3xl font-bold text-green-400">{stats.totalRequests}</div>
                          <div className="text-gray-400 text-sm">Total Requests</div>
                        </div>
                        <div className="bg-gray-700 rounded-lg p-4">
                          <div className="text-3xl font-bold text-red-400">{stats.totalMalicious}</div>
                          <div className="text-gray-400 text-sm">Threats Detected</div>
                        </div>
                        <div className="bg-gray-700 rounded-lg p-4">
                          <div className="text-3xl font-bold text-yellow-400">
                            {stats.totalRequests > 0 
                              ? ((stats.totalMalicious / stats.totalRequests) * 100).toFixed(1)
                              : 0}%
                          </div>
                          <div className="text-gray-400 text-sm">Threat Rate</div>
                        </div>
                      </div>

                      {/* Attack Types */}
                      {Object.keys(stats.attackTypes).length > 0 && (
                        <div className="bg-gray-700 rounded-lg p-4">
                          <h3 className="text-lg font-medium mb-4">Attack Types Detected</h3>
                          <div className="space-y-2">
                            {Object.entries(stats.attackTypes).map(([type, count]) => (
                              <div key={type} className="flex items-center justify-between">
                                <span className="text-gray-300">{type}</span>
                                <span className="text-red-400 font-medium">{count}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Recent Activity */}
                      {stats.recentActivity && stats.recentActivity.length > 0 && (
                        <div className="bg-gray-700 rounded-lg p-4">
                          <h3 className="text-lg font-medium mb-4">Recent Activity</h3>
                          <div className="space-y-3">
                            {stats.recentActivity.map((activity, index) => (
                              <div key={index} className="flex items-center justify-between py-2 border-b border-gray-600 last:border-0">
                                <div>
                                  <div className="font-medium">{activity.fileName}</div>
                                  <div className="text-sm text-gray-400">{formatDate(activity.uploadedAt)}</div>
                                </div>
                                <div className="text-right">
                                  <span className={`px-2 py-1 rounded text-sm ${
                                    activity.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                                    activity.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                                    'bg-yellow-500/20 text-yellow-400'
                                  }`}>
                                    {activity.status}
                                  </span>
                                  {activity.maliciousCount > 0 && (
                                    <div className="text-red-400 text-sm mt-1">
                                      {activity.maliciousCount} threats
                                    </div>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {stats.totalFiles === 0 && (
                        <div className="text-center py-8 text-gray-400">
                          <p>No analysis data available yet.</p>
                          <p className="text-sm">Upload and analyze files to see your reports.</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Profile;
