import { Navigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import UniqueLoading from './ui/grid-loading';

const ProtectedRoute = ({ children }) => {
  const { token, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="text-center">
          <UniqueLoading variant="squares" size="lg" className="mx-auto" text="Loading..." />
          <p className="text-gray-400 mt-4">Loading...</p>
        </div>
      </div>
    );
  }

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  return children;
};

export default ProtectedRoute;

