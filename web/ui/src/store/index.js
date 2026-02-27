import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { setAuthToken, authApi } from '../api/client';
import api from '../api/client';

export const useAuthStore = create(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: true,
      error: null,
      sessionExpired: false,
      sessionExpiredMessage: '',
      
      login: async (username, password) => {
        set({ isLoading: true, error: null });
        try {
          const response = await authApi.login({ username, password });
          const { token, refresh_token } = response.data;
          
          setAuthToken(token);
          localStorage.setItem('refreshToken', refresh_token);
          
          const meResponse = await api.get('/api/v1/auth/me');
          const user = meResponse.data;
          
          localStorage.setItem('token', token);
          localStorage.setItem('user', JSON.stringify(user));
          
          set({ 
            user, 
            token, 
            refreshToken: refresh_token,
            isAuthenticated: true, 
            isLoading: false,
            sessionExpired: false,
            sessionExpiredMessage: ''
          });
          return user;
        } catch (error) {
          const message = error.response?.data?.error || 'Login failed';
          set({ error: message, isLoading: false, isAuthenticated: false });
          throw new Error(message);
        }
      },
      
      logout: async () => {
        const token = localStorage.getItem('token');
        set({ isLoading: true });
        
        try {
          // Call logout API to invalidate token on backend
          await authApi.logout();
        } catch (error) {
          // Continue with logout even if API call fails
          console.warn('Logout API call failed:', error);
        }
        
        // Clear all auth data
        setAuthToken(null);
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
        
        set({ 
          user: null, 
          token: null, 
          refreshToken: null,
          isAuthenticated: false, 
          isLoading: false,
          sessionExpired: false,
          sessionExpiredMessage: ''
        });
      },
      
      setSessionExpired: (message = 'Your session has expired.') => {
        set({ 
          sessionExpired: true, 
          sessionExpiredMessage: message,
          isAuthenticated: false 
        });
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
        setAuthToken(null);
      },
      
      clearSessionExpired: () => {
        set({ 
          sessionExpired: false, 
          sessionExpiredMessage: ''
        });
      },
      
      clearError: () => set({ error: null }),
      
      setUser: (user) => set({ user }),
      
      setLoading: (isLoading) => set({ isLoading }),
      
      isAdmin: () => get().user?.role === 'admin',
      
      isAgent: () => get().user?.role === 'agent',
      
      isRegularUser: () => get().user?.role === 'user',
      
      initializeAuth: () => {
        const state = get();
        const token = localStorage.getItem('token');
        const refreshToken = localStorage.getItem('refreshToken');
        const user = localStorage.getItem('user');
        
        if (token && user) {
          setAuthToken(token);
          set({ 
            token, 
            refreshToken,
            user: JSON.parse(user), 
            isAuthenticated: true,
            isLoading: false 
          });
        } else {
          set({ isLoading: false });
        }
      }
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ 
        token: state.token, 
        user: state.user,
        refreshToken: state.refreshToken,
        isAuthenticated: state.isAuthenticated 
      }),
    }
  )
);

// Zones Store
export const useZonesStore = create((set, get) => ({
  zones: [],
  selectedZone: null,
  isLoading: false,
  error: null,
  
  setZones: (zones) => set({ zones }),
  setSelectedZone: (zone) => set({ selectedZone: zone }),
  
  addZone: (zone) => set((state) => ({ 
    zones: [...state.zones, zone] 
  })),
  
  updateZone: (id, data) => set((state) => ({
    zones: state.zones.map(z => z.id === id ? { ...z, ...data } : z)
  })),
  
  removeZone: (id) => set((state) => ({
    zones: state.zones.filter(z => z.id !== id)
  })),
  
  setLoading: (isLoading) => set({ isLoading }),
  setError: (error) => set({ error }),
}));

// UI Store
export const useUIStore = create((set) => ({
  sidebarOpen: true,
  theme: 'light',
  notifications: [],
  
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  setTheme: (theme) => set({ theme }),
  
  addNotification: (notification) => set((state) => ({
    notifications: [...state.notifications, { 
      id: Date.now(), 
      ...notification 
    }]
  })),
  
  removeNotification: (id) => set((state) => ({
    notifications: state.notifications.filter(n => n.id !== id)
  })),
  
  clearNotifications: () => set({ notifications: [] }),
}));
