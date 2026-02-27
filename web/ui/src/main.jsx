import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { setAuthToken } from './api/client';
import { useAuthStore } from './store';
import { NotificationsProvider } from './components/Notifications';
import './index.css';

// Initialize auth state from persisted store (if any)
const { initializeAuth, setSessionExpired } = useAuthStore.getState();
if (typeof initializeAuth === 'function') {
  initializeAuth();
}

// Handle session expiration events
if (typeof window !== 'undefined') {
  window.addEventListener('session-expired', (event) => {
    const reason = event.detail?.reason || 'session_timeout';
    let message = 'Your session has expired.';
    
    if (reason === 'refresh_failed') {
      message = 'Your session has expired. Please log in again.';
    } else if (reason === 'no_refresh_token') {
      message = 'Your session has expired. Please log in again.';
    } else if (reason === 'session_timeout') {
      message = 'Your session has expired due to inactivity.';
    }
    
    setSessionExpired(message);
  });
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
