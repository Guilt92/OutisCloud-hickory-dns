import React, { useState, useEffect, useRef } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
  Menu, X, LayoutDashboard, Globe, Users, Server, Settings, LogOut, ChevronDown, MapPin,
  BarChart3, Building2, Activity, Search, User, Radio, Network, RefreshCw, LifeBuoy, ShieldCheck,
} from 'lucide-react';
import { useAuthStore } from '../store';
import clsx from 'clsx';
import { Brand, ThemeToggle, ThemeSync } from './ui';

// Navigation is defined per role. Administrators get the whole control surface; customers only see
// their own zones, lookups, settings and help. (Routes are additionally protected in App.jsx and by the API.)
const ADMIN_NAV = [
  { title: 'Overview', items: [
    { to: '/admin', icon: LayoutDashboard, label: 'Overview', exact: true },
    { to: '/admin/metrics', icon: BarChart3, label: 'Analytics' },
  ]},
  { title: 'DNS', items: [
    { to: '/admin/zones', icon: Globe, label: 'Zones' },
    { to: '/admin/nameservers', icon: Network, label: 'Nameservers' },
    { to: '/admin/georules', icon: MapPin, label: 'GeoDNS' },
    { to: '/admin/dns-lookup', icon: Search, label: 'DNS Lookup' },
  ]},
  { title: 'Infrastructure', items: [
    { to: '/admin/servers', icon: Server, label: 'DNS Servers' },
    { to: '/admin/agents', icon: Radio, label: 'Agents' },
    { to: '/admin/config', icon: RefreshCw, label: 'Config Sync' },
  ]},
  { title: 'Administration', items: [
    { to: '/admin/tenants', icon: Building2, label: 'Tenants & Quotas' },
    { to: '/admin/users', icon: Users, label: 'Users & Roles' },
    { to: '/admin/audit', icon: Activity, label: 'Audit Log' },
    { to: '/admin/settings', icon: Settings, label: 'Settings' },
  ]},
];

const USER_NAV = [
  { title: null, items: [
    { to: '/user', icon: LayoutDashboard, label: 'Overview', exact: true },
    { to: '/user/zones', icon: Globe, label: 'My Zones' },
    { to: '/user/analytics', icon: BarChart3, label: 'Analytics' },
    { to: '/user/dns-lookup', icon: Search, label: 'DNS Lookup' },
  ]},
  { title: 'Account', items: [
    { to: '/user/settings', icon: Settings, label: 'Account & Security' },
    { to: '/user/help', icon: LifeBuoy, label: 'Help & Docs' },
  ]},
];

const CRUMBS = {
  admin: 'Overview', zones: 'Zones', records: 'Records', nameservers: 'Nameservers', georules: 'GeoDNS', 'dns-lookup': 'DNS Lookup',
  servers: 'DNS Servers', agents: 'Agents', config: 'Config Sync', users: 'Users & Roles', audit: 'Audit Log', settings: 'Settings',
  metrics: 'Analytics', analytics: 'Analytics', tenants: 'Tenants & Quotas', user: 'Overview', help: 'Help & Docs',
};

function NavItem({ to, icon: Icon, label, exact, onNavigate }) {
  return (
    <NavLink
      to={to}
      end={!!exact}
      onClick={onNavigate}
      className={({ isActive }) => clsx(
        'group flex items-center gap-3 px-3 py-2.5 rounded-[14px] text-[13px] font-medium transition-colors',
        isActive ? 'bg-accent text-on-accent' : 'text-muted hover:text-ink hover:bg-ink/[0.045]'
      )}
    >
      {({ isActive }) => (
        <>
          <Icon className={clsx('w-[17px] h-[17px] flex-shrink-0', isActive ? 'text-on-accent' : 'text-muted group-hover:text-ink')} />
          <span className="flex-1 truncate">{label}</span>
        </>
      )}
    </NavLink>
  );
}

function Breadcrumbs() {
  const { pathname } = useLocation();
  const parts = pathname.split('/').filter(Boolean);
  const labels = parts.filter((p) => CRUMBS[p]).map((p) => CRUMBS[p]);
  const dedup = labels.filter((c, i) => labels.indexOf(c) === i);
  return (
    <nav aria-label="Breadcrumb" className="hidden sm:flex items-center gap-2 text-[13px] text-muted min-w-0">
      <span>{parts[0] === 'admin' ? 'Admin' : 'Workspace'}</span>
      {dedup.filter((c) => c !== 'Overview' || dedup.length === 1).map((c, i, arr) => (
        <React.Fragment key={c + i}>
          <span aria-hidden="true" className="text-muted/50">/</span>
          <span className={i === arr.length - 1 ? 'text-ink font-medium truncate' : 'truncate'}>{c}</span>
        </React.Fragment>
      ))}
    </nav>
  );
}

export default function Layout({ children }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const userMenuRef = useRef(null);
  const { user, isAuthenticated, logout } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();
  const isAdmin = user?.role === 'admin';

  useEffect(() => { setMenuOpen(false); setUserMenuOpen(false); }, [location.pathname]);
  useEffect(() => {
    const onDown = (e) => { if (userMenuRef.current && !userMenuRef.current.contains(e.target)) setUserMenuOpen(false); };
    const onKey = (e) => { if (e.key === 'Escape') { setUserMenuOpen(false); setMenuOpen(false); } };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey); };
  }, []);

  // Prevent back button navigation after logout
  useEffect(() => {
    const handlePopState = () => {
      if (!isAuthenticated && window.location.pathname !== '/login') navigate('/login', { replace: true });
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, [isAuthenticated, navigate]);

  const handleLogout = async () => {
    await logout();
    window.history.replaceState(null, '', '/login');
    navigate('/login');
  };

  if (!isAuthenticated) {
    return (<><ThemeSync />{children}</>);
  }

  const nav = isAdmin ? ADMIN_NAV : USER_NAV;
  const settingsPath = isAdmin ? '/admin/settings' : '/user/settings';

  return (
    <div className="min-h-screen">
      <ThemeSync />
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-[80] btn-primary">Skip to content</a>

      {/* Sidebar */}
      <aside
        aria-label="Primary"
        className={clsx(
          'fixed top-0 left-0 z-40 h-full w-[264px] flex flex-col bg-surface border-r border-line transition-transform duration-200 lg:translate-x-0',
          menuOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        <div className="h-16 flex items-center justify-between px-5 border-b border-line">
          <Link to={isAdmin ? '/admin' : '/user'} aria-label="OutisCloud home"><Brand /></Link>
          <button className="btn-icon lg:hidden" onClick={() => setMenuOpen(false)} aria-label="Close menu"><X className="w-5 h-5" /></button>
        </div>

        <nav className="flex-1 overflow-y-auto scrollbar-thin px-3 py-5 space-y-6">
          {nav.map((group, gi) => (
            <div key={gi}>
              {group.title && <p className="px-3 mb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted">{group.title}</p>}
              <div className="space-y-0.5">
                {group.items.map((it) => <NavItem key={it.to} {...it} onNavigate={() => setMenuOpen(false)} />)}
              </div>
            </div>
          ))}
        </nav>

        <div className="p-3 border-t border-line text-[11px] text-muted flex items-center gap-2">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>{isAdmin ? 'Administrator workspace' : 'Customer workspace'}</span>
        </div>
      </aside>

      {menuOpen && <div className="fixed inset-0 z-30 bg-black/40 backdrop-blur-sm lg:hidden" onClick={() => setMenuOpen(false)} aria-hidden="true" />}

      {/* Top bar */}
      <header className="sticky top-0 z-20 lg:ml-[264px] h-16 flex items-center gap-3 px-4 sm:px-6 lg:px-8 border-b border-line bg-surface/80 backdrop-blur-xl">
        <button className="btn-icon lg:hidden" onClick={() => setMenuOpen(true)} aria-label="Open menu" aria-expanded={menuOpen}><Menu className="w-5 h-5" /></button>
        <div className="lg:hidden"><Brand compact /></div>
        <Breadcrumbs />
        <div className="flex-1" />
        <ThemeToggle />
        <div className="relative" ref={userMenuRef}>
          <button
            onClick={() => setUserMenuOpen((v) => !v)}
            className="flex items-center gap-2.5 pl-1 pr-2 py-1 rounded-[14px] hover:bg-ink/5 transition-colors"
            aria-haspopup="menu" aria-expanded={userMenuOpen} data-testid="user-menu"
          >
            <span className="w-8 h-8 rounded-full bg-accent text-on-accent flex items-center justify-center text-sm font-semibold">
              {user?.username?.charAt(0).toUpperCase() || 'U'}
            </span>
            <span className="hidden sm:block text-left leading-tight">
              <span className="block text-[13px] font-medium text-ink">{user?.username || 'User'}</span>
              <span className="block text-[11px] text-muted capitalize">{user?.role || 'user'}</span>
            </span>
            <ChevronDown className="w-4 h-4 text-muted" />
          </button>
          {userMenuOpen && (
            <div role="menu" className="absolute right-0 top-full mt-2 w-56 card shadow-pop py-1.5 animate-fade-in z-50">
              <Link role="menuitem" to={settingsPath} className="flex items-center gap-2 px-4 py-2.5 text-sm text-ink hover:bg-ink/5"><User className="w-4 h-4 text-muted" />Account & security</Link>
              <hr className="my-1.5 border-line" />
              <button role="menuitem" onClick={handleLogout} className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-danger-600 dark:text-danger-400 hover:bg-danger-500/[0.07]"><LogOut className="w-4 h-4" />Sign out</button>
            </div>
          )}
        </div>
      </header>

      <main id="main" className="lg:ml-[264px]">
        <div className="px-4 sm:px-6 lg:px-8 py-6 lg:py-8 max-w-[1280px] mx-auto">{children}</div>
      </main>
    </div>
  );
}
