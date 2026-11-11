import React, { useState, useEffect } from 'react';
import { useNavigate, Navigate, useSearchParams } from 'react-router-dom';
import { User, Lock, AlertCircle, Eye, EyeOff, Loader2, ShieldCheck, Zap, MapPin, Radio } from 'lucide-react';
import { useAuthStore } from '../store';
import clsx from 'clsx';
import { Brand, FlowArt, ThemeToggle } from '../components/ui';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [otp, setOtp] = useState('');
  const [needOtp, setNeedOtp] = useState(false);
  
  const { login, isAuthenticated, user, sessionExpired, sessionExpiredMessage, clearSessionExpired } = useAuthStore();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  
  // Check if user was redirected due to session expiration
  const sessionExpiredParam = searchParams.get('expired');
  
  useEffect(() => {
    // Clear session expired state when mounting login page
    if (sessionExpired) {
      clearSessionExpired();
    }
    
    // Prevent back button navigation after logout
    const handlePopState = (event) => {
      if (window.location.pathname === '/login') {
        // Allow staying on login page
      }
    };
    
    window.history.pushState(null, '', window.location.href);
    
    const handleBeforeUnload = () => {
      window.history.pushState(null, '', window.location.href);
    };
    
    window.addEventListener('popstate', handlePopState);
    window.addEventListener('beforeunload', handleBeforeUnload);
    
    return () => {
      window.removeEventListener('popstate', handlePopState);
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [sessionExpired, clearSessionExpired]);
  
  if (isAuthenticated) {
    return <Navigate to={user?.role === 'admin' ? '/admin' : '/user'} replace />;
  }
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    if (!username.trim()) {
      setError('Username is required');
      return;
    }
    if (!password) {
      setError('Password is required');
      return;
    }
    if (username.length < 3) {
      setError('Username must be at least 3 characters');
      return;
    }
    
    setIsLoading(true);
    
    try {
      const user = await login(username, password, otp);
      navigate(user?.role === 'admin' ? '/admin' : '/user');
    } catch (err) {
      if (err.message === 'mfa_required') { setNeedOtp(true); setError('Enter the 6-digit code from your authenticator app'); }
      else setError(err.message || 'Invalid username or password');
    } finally {
      setIsLoading(false);
    }
  };

  const showSessionExpiredMessage = sessionExpiredParam === 'true' || sessionExpired;

  const features = [
    { icon: Zap, label: 'Fast authoritative DNS', desc: 'Hot-reloaded zones, no downtime' },
    { icon: ShieldCheck, label: 'DNSSEC built in', desc: 'Signing, DS records, key rollover' },
    { icon: MapPin, label: 'GeoDNS', desc: 'Country, region and city routing' },
    { icon: Radio, label: 'Replicated', desc: 'Signed config sync to every node' },
  ];

  return (
    <div className="min-h-screen flex" data-testid="login-page">
      {/* Brand panel */}
      <div className="hidden lg:flex lg:w-[52%] relative overflow-hidden bg-[#0B0D12] text-white">
        <FlowArt className="absolute inset-0 w-full h-full opacity-90" />
        <div className="absolute inset-0 bg-[radial-gradient(60%_50%_at_20%_10%,rgba(245,240,32,0.10),transparent_70%)]" />
        <div className="relative z-10 flex flex-col justify-between w-full p-12 xl:p-16">
          <span className="inline-flex items-center gap-2.5"><span className="inline-block"><Brand /></span></span>
          <div className="max-w-lg">
            <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[#F5F020] mb-4">DNS control plane</p>
            <h1 className="font-display text-5xl xl:text-6xl font-semibold tracking-tight leading-[1.05]">DNS that moves at the speed of your data.</h1>
            <p className="mt-5 text-lg text-white/70">One place to run zones, servers, agents and GeoDNS — with the audit trail to prove it.</p>
            <ul className="mt-10 grid grid-cols-2 gap-x-8 gap-y-6">
              {features.map((f) => (
                <li key={f.label} className="flex gap-3">
                  <f.icon className="w-5 h-5 text-[#F5F020] flex-shrink-0 mt-0.5" />
                  <div><p className="text-sm font-semibold">{f.label}</p><p className="text-xs text-white/60 mt-0.5">{f.desc}</p></div>
                </li>
              ))}
            </ul>
          </div>
          <p className="text-xs text-white/40">&copy; {new Date().getFullYear()} OutisCloud</p>
        </div>
      </div>

      {/* Form */}
      <div className="w-full lg:w-[48%] flex flex-col">
        <div className="flex items-center justify-between p-4 lg:p-6">
          <div className="lg:hidden"><Brand /></div>
          <div className="flex-1" />
          <ThemeToggle />
        </div>
        <div className="flex-1 flex items-center justify-center px-5 pb-10">
          <div className="w-full max-w-md animate-slide-in">
            <p className="eyebrow mb-2">Sign in</p>
            <h2 className="font-display text-3xl font-semibold tracking-tight text-ink">Welcome back</h2>
            <p className="text-muted mt-1.5 mb-7">Sign in to manage your DNS.</p>

            {showSessionExpiredMessage && (
              <div role="status" className="mb-5 p-3.5 rounded-lg border border-warning-500/40 bg-warning-500/10 flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-warning-500 mt-0.5 flex-shrink-0" />
                <p className="text-sm text-ink">Your session has expired. Please log in again.</p>
              </div>
            )}
            {error && (
              <div role="alert" className="mb-5 p-3.5 rounded-lg border border-danger-500/40 bg-danger-500/10 flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-danger-500 mt-0.5 flex-shrink-0" />
                <p className="text-sm text-ink">{error}</p>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-5" noValidate>
              <div>
                <label htmlFor="username" className="form-label">Username</label>
                <div className="relative">
                  <User className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted pointer-events-none" />
                  <input id="username" type="text" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)}
                    className={clsx('input pl-10 py-3', error && !username && 'input-error')} placeholder="Enter your username" />
                </div>
              </div>
              <div>
                <label htmlFor="password" className="form-label">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted pointer-events-none" />
                  <input id="password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)}
                    className={clsx('input pl-10 pr-11 py-3', error && !password && 'input-error')} placeholder="Enter your password" />
                  <button type="button" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? 'Hide password' : 'Show password'}
                    className="absolute inset-y-0 right-0 px-3.5 flex items-center text-muted hover:text-ink">
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>
              {needOtp && (
                <div>
                  <label htmlFor="otp" className="form-label">Authentication code</label>
                  <input id="otp" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={otp}
                    onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))} className="input py-3 font-mono tracking-[0.4em] text-center" placeholder="123456" />
                </div>
              )}
              <button type="submit" disabled={isLoading} className="btn-primary w-full py-3 text-sm">
                {isLoading ? (<><Loader2 className="w-4 h-4 animate-spin" /><span>Signing in…</span></>) : 'Sign in'}
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
