import React, { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import { useAuthStore } from './store';
import { Outlet } from 'react-router-dom';

// Route-based code-splitting using React.lazy
const Login = lazy(() => import('./pages/Login'));
const AdminDashboard = lazy(() => import('./pages/Admin/Dashboard'));
const AdminZones = lazy(() => import('./pages/Admin/Zones'));
const AdminUsers = lazy(() => import('./pages/Admin/Users'));
const AdminServers = lazy(() => import('./pages/Admin/Servers'));
const AdminAgents = lazy(() => import('./pages/Admin/Agents'));
const AdminGeoRules = lazy(() => import('./pages/Admin/GeoRules'));
const AdminConfigPush = lazy(() => import('./pages/Admin/ConfigPush'));
const AdminAuditLogs = lazy(() => import('./pages/Admin/AuditLogs'));
const Records = lazy(() => import('./pages/Records'));
const UserDashboard = lazy(() => import('./pages/User'));

function ProtectedRoute({ children, requireAdmin = false }) {
  const { isAuthenticated, user } = useAuthStore();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (requireAdmin && user?.role !== 'admin') {
    return <Navigate to="/user" replace />;
  }

  return children;
}

export default function App() {
  const { isAuthenticated, user } = useAuthStore();

  // Redirect authenticated users away from /login
  if (isAuthenticated && window.location.pathname === '/login') {
    return <Navigate to={user?.role === 'admin' ? '/admin' : '/user'} replace />;
  }

  return (
    <Layout>
      <Suspense fallback={<div className="p-4">Loading…</div>}>
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
            <Route path="users" element={<AdminUsers />} />
            <Route path="servers" element={<AdminServers />} />
            <Route path="agents" element={<AdminAgents />} />
            <Route path="georules" element={<AdminGeoRules />} />
            <Route path="metrics" element={<AdminDashboard />} />
            <Route path="audit" element={<AdminAuditLogs />} />
            <Route path="certificates" element={<AdminDashboard />} />
            <Route path="config" element={<AdminConfigPush />} />
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
