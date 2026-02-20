import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { setAuthToken } from './api/client';
import { useAuthStore } from './store';
import { NotificationsProvider } from './components/Notifications';
import './index.css';

// Initialize auth state from persisted store (if any)
const { initializeAuth } = useAuthStore.getState();
if (typeof initializeAuth === 'function') {
  initializeAuth();
}

const container = document.getElementById('root');
const root = createRoot(container);

root.render(
  <React.StrictMode>
    <BrowserRouter>
      <NotificationsProvider>
        <App />
      </NotificationsProvider>
    </BrowserRouter>
  </React.StrictMode>
);
