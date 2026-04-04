import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import LandingPage from './pages/LandingPage';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Requests from './pages/Requests';
import Analysis from './pages/Analysis';
import Upload from './pages/Upload';
import Profile from './pages/Profile';
import AIAssistant from './pages/AIAssistant';

function App() {
  return (
    <AuthProvider>
      <ThemeProvider>
        <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <Routes>
            {/* Public Routes */}
            <Route path="/" element={<LandingPage />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />

            {/* Protected Routes */}
            <Route path="/app" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
              <Route index element={<Navigate to="/app/dashboard" replace />} />
              <Route path="dashboard" element={<Dashboard />} />
              <Route path="requests" element={<Requests />} />
              <Route path="analysis" element={<Analysis />} />
              <Route path="upload" element={<Upload />} />
              <Route path="ai" element={<AIAssistant />} />
              <Route path="profile" element={<Profile />} />
            </Route>

            {/* Legacy routes redirect */}
            <Route path="/dashboard" element={<Navigate to="/app/dashboard" replace />} />
            <Route path="/requests" element={<Navigate to="/app/requests" replace />} />
            <Route path="/analysis" element={<Navigate to="/app/analysis" replace />} />
            <Route path="/upload" element={<Navigate to="/app/upload" replace />} />
            <Route path="/profile" element={<Navigate to="/app/profile" replace />} />

            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </ThemeProvider>
    </AuthProvider>
  );
}

export default App;
