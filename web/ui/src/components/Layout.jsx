import React, { useState, useEffect, useRef } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { 
  Menu, 
  X, 
  Home, 
  Globe, 
  FileText, 
  Users, 
  Server, 
  Settings, 
  LogOut,
  ChevronDown,
  MapPin,
  Key,
  BarChart3,
  Activity,
  Moon,
  Sun,
  Search,
  User,
  Lock
} from 'lucide-react';
import { useAuthStore, useUIStore } from '../store';
import clsx from 'clsx';

const NavItem = ({ to, icon: Icon, label, badge, exact }) => {
  const location = useLocation();
  const isActive = exact 
    ? location.pathname === to 
    : location.pathname === to || location.pathname.startsWith(to + '/');
  
  return (
    <Link
      to={to}
      className={clsx(
        'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200',
        isActive 
          ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/30 dark:text-primary-300' 
          : 'text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700/50'
      )}
    >
      <Icon className={clsx("w-5 h-5", isActive && "text-primary-600 dark:text-primary-400")} />
      <span className="flex-1">{label}</span>
      {badge && (
        <span className="px-2 py-0.5 text-xs font-semibold bg-primary-100 text-primary-700 rounded-full dark:bg-primary-900 dark:text-primary-300">
          {badge}
        </span>
      )}
    </Link>
  );
};

export default function Layout({ children }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const userMenuRef = useRef(null);
  const { user, isAuthenticated, logout } = useAuthStore();
  const { theme, toggleTheme } = useUIStore();
  const navigate = useNavigate();
  
  // Close user menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target)) {
        setUserMenuOpen(false);
      }
    };
    
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);
  
  // Prevent back button navigation after logout
  useEffect(() => {
    const handlePopState = (event) => {
      if (!isAuthenticated && window.location.pathname !== '/login') {
        navigate('/login', { replace: true });
      }
    };
    
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, [isAuthenticated, navigate]);
  
  const handleLogout = async () => {
    await logout();
    // Clear browser history to prevent back button
    window.history.replaceState(null, '', '/login');
    navigate('/login');
  };
  
  const isAdmin = user?.role === 'admin';
  const isAgent = user?.role === 'agent';
  
  const adminNavItems = [
    { to: '/admin', icon: Home, label: 'Dashboard', exact: true },
    { to: '/admin/zones', icon: Globe, label: 'Zones' },
    { to: '/admin/records', icon: FileText, label: 'Records' },
    { to: '/admin/nameservers', icon: Globe, label: 'Nameservers' },
    { to: '/admin/dns-lookup', icon: Search, label: 'DNS Lookup' },
    { to: '/admin/users', icon: Users, label: 'Users' },
    { to: '/admin/servers', icon: Server, label: 'DNS Servers' },
    { to: '/admin/agents', icon: Server, label: 'Agents' },
    { to: '/admin/georules', icon: MapPin, label: 'GeoDNS' },
    { to: '/admin/certificates', icon: Key, label: 'SSL' },
    { to: '/admin/metrics', icon: BarChart3, label: 'Metrics' },
    { to: '/admin/audit', icon: Activity, label: 'Audit Logs' },
    { to: '/admin/settings', icon: Settings, label: 'Settings' },
  ];
  
  const userNavItems = [
    { to: '/user', icon: Home, label: 'Dashboard', exact: true },
    { to: '/user/dns-lookup', icon: Search, label: 'DNS Lookup' },
  ];
  
  // Agents can see some admin items but not all
  const agentNavItems = [
    { to: '/admin', icon: Home, label: 'Dashboard', exact: true },
    { to: '/admin/zones', icon: Globe, label: 'Zones' },
    { to: '/admin/records', icon: FileText, label: 'Records' },
    { to: '/admin/nameservers', icon: Globe, label: 'Nameservers' },
    { to: '/admin/dns-lookup', icon: Search, label: 'DNS Lookup' },
    { to: '/admin/georules', icon: MapPin, label: 'GeoDNS' },
  ];
  
  let navItems;
  if (isAdmin) {
    navItems = adminNavItems;
  } else if (isAgent) {
    navItems = agentNavItems;
  } else {
    navItems = userNavItems;
  }
  
  // Initialize theme
  React.useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [theme]);
  
  const toggleThemeHandler = () => {
    useUIStore.getState().setTheme(theme === 'dark' ? 'light' : 'dark');
  };
  
  if (!isAuthenticated) {
    return <>{children}</>;
  }
  
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Mobile menu button */}
      <div className="lg:hidden fixed top-0 left-0 right-0 z-50 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-4 py-3 flex items-center justify-between">
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="p-2 rounded-lg text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700"
        >
          {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
        <h1 className="text-lg font-semibold text-gray-900 dark:text-white">OutisCloud</h1>
        <div className="flex items-center gap-2">
          <button
            onClick={toggleThemeHandler}
            className="p-2 rounded-lg text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700"
          >
            {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
          </button>
        </div>
      </div>
      
      {/* Sidebar */}
      <aside
        className={clsx(
          "fixed top-0 left-0 z-40 h-full w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 transition-transform duration-300 lg:translate-x-0",
          mobileMenuOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        {/* Logo */}
        <div className="h-16 flex items-center px-6 border-b border-gray-200 dark:border-gray-700">
          <Globe className="w-8 h-8 text-primary-600" />
          <span className="ml-2 text-xl font-bold text-gray-900 dark:text-white">OutisCloud</span>
        </div>
        
        {/* Navigation */}
        <nav className="p-4 space-y-1 overflow-y-auto h-[calc(100vh-8rem)]">
          {navItems.map((item) => (
            <NavItem 
              key={item.to} 
              to={item.to} 
              icon={item.icon} 
              label={item.label}
              badge={item.badge}
              exact={item.exact}
            />
          ))}
        </nav>
        
        {/* User section */}
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-gray-200 dark:border-gray-700">
          <div className="relative" ref={userMenuRef}>
            <button
              onClick={() => setUserMenuOpen(!userMenuOpen)}
              className="w-full flex items-center gap-3 p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              <div className="w-8 h-8 rounded-full bg-primary-100 dark:bg-primary-900 flex items-center justify-center">
                <span className="text-sm font-medium text-primary-700 dark:text-primary-300">
                  {user?.username?.charAt(0).toUpperCase() || 'U'}
                </span>
              </div>
              <div className="flex-1 text-left">
                <p className="text-sm font-medium text-gray-900 dark:text-white">{user?.username || 'User'}</p>
                <p className="text-xs text-gray-500 dark:text-gray-400 capitalize">{user?.role || 'user'}</p>
              </div>
              <ChevronDown className="w-4 h-4 text-gray-500" />
            </button>
            
            {userMenuOpen && (
              <div className="absolute bottom-full left-0 right-0 mb-2 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 py-2 animate-fade-in z-50">
                <Link
                  to={isAdmin ? "/admin/settings" : "/user/settings"}
                  className="flex items-center gap-2 px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                  onClick={() => setUserMenuOpen(false)}
                >
                  <User className="w-4 h-4" />
                  Profile
                </Link>
                <Link
                  to={isAdmin ? "/admin/settings" : "/user/settings"}
                  className="flex items-center gap-2 px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                  onClick={() => setUserMenuOpen(false)}
                >
                  <Lock className="w-4 h-4" />
                  Change Password
                </Link>
                <hr className="my-2 border-gray-200 dark:border-gray-700" />
                <button
                  onClick={handleLogout}
                  className="w-full flex items-center gap-2 px-4 py-2 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20"
                >
                  <LogOut className="w-4 h-4" />
                  Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </aside>
      
      {/* Mobile overlay */}
      {mobileMenuOpen && (
        <div 
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}
      
      {/* Main content */}
      <main className="lg:ml-64 pt-16 lg:pt-0">
        <div className="p-4 lg:p-8 mt-16 lg:mt-0">
          {children}
        </div>
      </main>
    </div>
  );
}
