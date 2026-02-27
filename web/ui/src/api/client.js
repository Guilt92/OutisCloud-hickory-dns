import axios from 'axios';

// Default to relative API path so the production build works behind a reverse
// proxy (nginx) which proxies `/api` to the control API container. During
// local development the VITE_API_BASE_URL env var can override this.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Store for refresh token
let refreshTokenPromise = null;
let lastActivityTime = Date.now();

// Activity tracking for session timeout
const INACTIVITY_TIMEOUT = 15 * 60 * 1000; // 15 minutes

const updateActivity = () => {
  lastActivityTime = Date.now();
};

// Track user activity
if (typeof window !== 'undefined') {
  ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
    window.addEventListener(event, updateActivity, { passive: true });
  });
  
  // Check for inactivity every minute
  setInterval(() => {
    const token = localStorage.getItem('token');
    if (token && Date.now() - lastActivityTime > INACTIVITY_TIMEOUT) {
      // Session expired due to inactivity
      localStorage.removeItem('token');
      localStorage.removeItem('refreshToken');
      localStorage.removeItem('user');
      window.dispatchEvent(new CustomEvent('session-expired'));
    }
  }, 60000);
}

// Request interceptor for auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor for error handling, token refresh, and session expiration
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    // Handle 401 errors - try to refresh token
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      const refreshToken = localStorage.getItem('refreshToken');
      
      if (refreshToken) {
        try {
          if (!refreshTokenPromise) {
            refreshTokenPromise = axios.post(`${API_BASE_URL}/api/v1/auth/refresh`, 
              { refresh_token: refreshToken },
              { headers: { 'Content-Type': 'application/json' } }
            );
          }
          
          const response = await refreshTokenPromise;
          refreshTokenPromise = null;
          
          const { token, refresh_token } = response.data;
          localStorage.setItem('token', token);
          localStorage.setItem('refreshToken', refresh_token);
          
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return api(originalRequest);
        } catch (refreshError) {
          refreshTokenPromise = null;
          // Refresh failed, force logout
          localStorage.removeItem('token');
          localStorage.removeItem('refreshToken');
          localStorage.removeItem('user');
          window.dispatchEvent(new CustomEvent('session-expired', { detail: { reason: 'refresh_failed' } }));
        }
      } else {
        // No refresh token, force logout
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
        window.dispatchEvent(new CustomEvent('session-expired', { detail: { reason: 'no_refresh_token' } }));
      }
    }
    
    // Handle other auth errors
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('refreshToken');
      localStorage.removeItem('user');
      window.dispatchEvent(new CustomEvent('session-expired'));
    }
    
    return Promise.reject(error);
  }
);

// Normalize API responses - backend returns inconsistent formats
api.interceptors.response.use(
  (response) => {
    if (response.data && typeof response.data === 'object') {
      if (response.data.success === true && 'data' in response.data && response.data.data !== undefined) {
        return {
          ...response,
          data: response.data.data
        };
      }
    }
    return response;
  },
  (error) => {
    // Error normalization is handled above
    return Promise.reject(error);
  }
);

// ==================== Auth API ====================
export const authApi = {
  login: (credentials) => api.post('/api/v1/auth/login', credentials),
  logout: () => api.post('/api/v1/auth/logout'),
  refreshToken: () => api.post('/api/v1/auth/refresh'),
  changePassword: (data) => api.post('/api/v1/auth/change-password', data),
  adminResetPassword: (data) => api.post('/api/v1/auth/admin-reset-password', data),
  getCurrentUser: () => api.get('/api/v1/auth/me'),
};

// ==================== Users API ====================
export const usersApi = {
  list: () => api.get('/api/v1/users'),
  get: (id) => api.get(`/api/v1/users/${id}`),
  create: (userData) => api.post('/api/v1/users', userData),
  update: (id, userData) => api.put(`/api/v1/users/${id}`, userData),
  delete: (id) => api.delete(`/api/v1/users/${id}`),
  changePassword: (id, passwords) => api.post(`/api/v1/users/${id}/password`, passwords),
};

// ==================== Zones API ====================
export const zonesApi = {
  list: () => api.get('/api/v1/zones'),
  get: (id) => api.get(`/api/v1/zones/${id}`),
  create: (zoneData) => api.post('/api/v1/zones', zoneData),
  update: (id, zoneData) => api.put(`/api/v1/zones/${id}`, zoneData),
  delete: (id) => api.delete(`/api/v1/zones/${id}`),
  getRecords: (zoneId) => api.get(`/api/v1/zones/${zoneId}/records`),
  createRecord: (zoneId, recordData) => api.post(`/api/v1/zones/${zoneId}/records`, recordData),
  updateRecord: (zoneId, recordId, recordData) => api.put(`/api/v1/zones/${zoneId}/records/${recordId}`, recordData),
  deleteRecord: (zoneId, recordId) => api.delete(`/api/v1/zones/${zoneId}/records/${recordId}`),
  importZone: (zoneId, data) => api.post(`/api/v1/zones/${zoneId}/import`, data),
  exportZone: (zoneId) => api.get(`/api/v1/zones/${zoneId}/export`),
};

// ==================== Servers API ====================
export const serversApi = {
  list: () => api.get('/api/v1/servers'),
  get: (id) => api.get(`/api/v1/servers/${id}`),
  create: (serverData) => api.post('/api/v1/servers', serverData),
  update: (id, serverData) => api.put(`/api/v1/servers/${id}`, serverData),
  delete: (id) => api.delete(`/api/v1/servers/${id}`),
  start: (id) => api.post(`/api/v1/servers/${id}/start`),
  stop: (id) => api.post(`/api/v1/servers/${id}/stop`),
  restart: (id) => api.post(`/api/v1/servers/${id}/restart`),
  getStatus: (id) => api.get(`/api/v1/servers/${id}/status`),
};

// ==================== Nameservers API ====================
export const nameserversApi = {
  list: () => api.get('/api/v1/nameservers'),
  get: (id) => api.get(`/api/v1/nameservers/${id}`),
  create: (nsData) => api.post('/api/v1/nameservers', nsData),
  update: (id, nsData) => api.put(`/api/v1/nameservers/${id}`, nsData),
  delete: (id) => api.delete(`/api/v1/nameservers/${id}`),
};

// ==================== DNS Control API ====================
// only generation endpoint remains; the DNS server is managed separately
export const dnsApi = {
  generate: () => api.post('/api/v1/dns/generate'),
};

// ==================== Agents API ====================
export const agentsApi = {
  list: () => api.get('/api/v1/agents'),
  get: (id) => api.get(`/api/v1/agents/${id}`),
  register: (agentData) => api.post('/api/v1/agents/register', agentData),
  heartbeat: (agentData) => api.post('/api/v1/agents/heartbeat', agentData),
  getConfig: (id) => api.get(`/api/v1/agents/${id}/config`),
  rotateToken: (id) => api.post(`/api/v1/agents/${id}/token/rotate`),
  delete: (id) => api.delete(`/api/v1/agents/${id}`),
  pushConfig: (agentId, config) => api.post('/api/v1/agents/push-config', { agentId, config }),
};

// ==================== GeoRules API ====================
export const geoRulesApi = {
  list: () => api.get('/api/v1/georules'),
  get: (id) => api.get(`/api/v1/georules/${id}`),
  create: (ruleData) => api.post('/api/v1/georules', ruleData),
  update: (id, ruleData) => api.put(`/api/v1/georules/${id}`, ruleData),
  delete: (id) => api.delete(`/api/v1/georules/${id}`),
  test: (testData) => api.post('/api/v1/georules/resolve', testData),
  getStats: () => api.get('/api/v1/georules/stats'),
};

// ==================== SSL Certificates API ====================
export const certificatesApi = {
  list: () => api.get('/api/v1/certificates'),
  get: (id) => api.get(`/api/v1/certificates/${id}`),
  create: (certData) => api.post('/api/v1/certificates', certData),
  renew: (id) => api.post(`/api/v1/certificates/${id}/renew`),
  revoke: (id) => api.post(`/api/v1/certificates/${id}/revoke`),
  delete: (id) => api.delete(`/api/v1/certificates/${id}`),
  getStatus: (id) => api.get(`/api/v1/certificates/${id}/status`),
};

// ==================== Metrics API ====================
export const metricsApi = {
  get: () => api.get('/metrics'),
  getPrometheus: () => api.get('/api/v1/metrics'),
  getQueryRate: () => api.get('/api/v1/metrics/queries'),
  getCacheStats: () => api.get('/api/v1/metrics/cache'),
  getGeoStats: () => api.get('/api/v1/metrics/geo'),
  getAgentStats: () => api.get('/api/v1/metrics/agents'),
};

// ==================== Audit Logs API ====================
export const auditApi = {
  list: (params) => api.get('/api/v1/audit/logs', { params }),
  get: (id) => api.get(`/api/v1/audit/logs/${id}`),
};

// ==================== Health Check API ====================
export const healthApi = {
  check: () => api.get('/health'),
  ready: () => api.get('/ready'),
};

// Helper function to set token
export const setAuthToken = (token) => {
  if (token) {
    localStorage.setItem('token', token);
    api.defaults.headers.common.Authorization = `Bearer ${token}`;
  } else {
    localStorage.removeItem('token');
    delete api.defaults.headers.common.Authorization;
  }
};

// Alias for setToken compatibility
api.setToken = setAuthToken;

// Helper to get stored token
export const getAuthToken = () => localStorage.getItem('token');

export default api;
