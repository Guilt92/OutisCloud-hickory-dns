import React, { Suspense, lazy, useEffect } from 'react';
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import Layout from './components/Layout';
import { useAuthStore } from './store';
import { Outlet } from 'react-router-dom';

// Route-based code-splitting using React.lazy
const Login = lazy(() => import('./pages/Login'));
const AdminDashboard = lazy(() => import('./pages/Admin/Dashboard'));
const AdminZones = lazy(() => import('./pages/Admin/Zones'));
const AdminUsers = lazy(() => import('./pages/Admin/Users'));
const AdminServers = lazy(() => import('./pages/Admin/Servers'));
const AdminNameservers = lazy(() => import('./pages/Admin/Nameservers'));
const AdminAgents = lazy(() => import('./pages/Admin/Agents'));
const AdminGeoRules = lazy(() => import('./pages/Admin/GeoRules'));
const AdminConfigPush = lazy(() => import('./pages/Admin/ConfigPush'));
const AdminAuditLogs = lazy(() => import('./pages/Admin/AuditLogs'));
const AdminDnsLookup = lazy(() => import('./pages/Admin/DnsLookup'));
const AdminSettings = lazy(() => import('./pages/Admin/Settings'));
const Records = lazy(() => import('./pages/Records'));
const UserDashboard = lazy(() => import('./pages/User'));

function ProtectedRoute({ children, requireAdmin = false }) {
  const { isAuthenticated, user, sessionExpired } = useAuthStore();

  if (sessionExpired) {
    return <Navigate to="/login?expired=true" replace />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (requireAdmin && user?.role !== 'admin') {
    return <Navigate to="/user" replace />;
  }

  return children;
}

function LoadingScreen() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
      <div className="text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mx-auto mb-4"></div>
        <p className="text-gray-600 dark:text-gray-400">Loading...</p>
      </div>
    </div>
  );
}

export default function App() {
  const { isAuthenticated, user, isLoading, sessionExpired, sessionExpiredMessage } = useAuthStore();
  const navigate = useNavigate();
  
  // Handle session expiration redirect
  useEffect(() => {
    if (sessionExpired && window.location.pathname !== '/login') {
      navigate('/login?expired=true', { replace: true });
    }
  }, [sessionExpired, navigate]);

  // Redirect authenticated users away from /login
  if (isAuthenticated && window.location.pathname === '/login') {
    return <Navigate to={user?.role === 'admin' ? '/admin' : '/user'} replace />;
  }

  // Show loading screen while checking auth state
  if (isLoading) {
    return <LoadingScreen />;
  }

  return (
    <Layout>
      <Suspense fallback={<LoadingScreen />}>
        <Routes>
          <Route path="/login" element={<Login />} />

          <Route
            path="/admin/*"
            element={
              <ProtectedRoute requireAdmin>
                <Outlet />
              </ProtectedRoute>
            }
          >
            <Route index element={<AdminDashboard />} />
            <Route path="zones" element={<AdminZones />} />
            <Route path="zones/:id/records" element={<Records />} />
            <Route path="dns-lookup" element={<AdminDnsLookup />} />
            <Route path="users" element={<AdminUsers />} />
            <Route path="servers" element={<AdminServers />} />
            <Route path="nameservers" element={<AdminNameservers />} />
            <Route path="agents" element={<AdminAgents />} />
            <Route path="georules" element={<AdminGeoRules />} />
            <Route path="metrics" element={<AdminDashboard />} />
            <Route path="audit" element={<AdminAuditLogs />} />
            <Route path="certificates" element={<AdminDashboard />} />
            <Route path="config" element={<AdminConfigPush />} />
            <Route path="settings" element={<AdminSettings />} />
          </Route>

          <Route
            path="/user/*"
            element={
              <ProtectedRoute>
                <Outlet />
              </ProtectedRoute>
            }
          >
            <Route index element={<UserDashboard />} />
            <Route path="dns-lookup" element={<AdminDnsLookup />} />
            <Route path="settings" element={<AdminSettings />} />
          </Route>

          <Route
            path="/"
            element={
              isAuthenticated
                ? <Navigate to={user?.role === 'admin' ? '/admin' : '/user'} replace />
                : <Navigate to="/login" replace />
            }
          />

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </Layout>
  );
}
