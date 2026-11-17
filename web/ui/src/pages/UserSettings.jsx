import React from 'react';
import { motion } from 'framer-motion';
import { Palette, User, Globe, Sun, Moon, Settings as SettingsIcon } from 'lucide-react';
import { useUIStore, useAuthStore } from '../store';
import PasswordChangeForm from '../components/PasswordChangeForm';
import MfaCard from '../components/MfaCard';
import { PageHeader } from '../components/ui';

export default function UserSettings() {
  const { theme, setTheme } = useUIStore();
  const { user } = useAuthStore();

  return (
    <div className="space-y-6 max-w-4xl">
      <PageHeader title="Settings" description="Manage appearance, your account and security." icon={SettingsIcon} />

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="card p-6"
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="icon-box">
            <Palette className="w-5 h-5" />
          </div>
          <div>
            <h2 className="font-display text-lg font-semibold tracking-[-0.02em] text-ink">Appearance</h2>
            <p className="text-sm text-muted">Customise the look and feel.</p>
          </div>
        </div>

        <div className="space-y-4">
          <span className="form-label">Theme</span>
          <div className="grid grid-cols-2 gap-3">
            {[{ value: 'light', label: 'Light', icon: Sun }, { value: 'dark', label: 'Dark', icon: Moon }].map(({ value, label, icon: Icon }) => (
              <button
                key={value}
                onClick={() => setTheme(value)}
                aria-pressed={theme === value}
                className={`flex items-center gap-3 p-4 rounded-[14px] border transition-colors ${
                  theme === value ? 'border-ink bg-surface-2' : 'border-line hover:border-muted/40'
                }`}
              >
                <Icon className={`w-5 h-5 ${theme === value ? 'text-ink' : 'text-muted'}`} />
                <span className="font-medium text-ink">{label}</span>
              </button>
            ))}
          </div>
        </div>
      </motion.div>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="card p-6"
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="icon-box">
            <User className="w-5 h-5" />
          </div>
          <div>
            <h2 className="font-display text-lg font-semibold tracking-[-0.02em] text-ink">Profile</h2>
            <p className="text-sm text-muted">Your account information.</p>
          </div>
        </div>

        <div className="space-y-4">
          <div className="flex items-center gap-4 p-4 rounded-[14px] bg-surface-2">
            <div className="w-12 h-12 rounded-full bg-accent text-on-accent flex items-center justify-center font-semibold text-xl font-bold">
              {user?.username?.charAt(0).toUpperCase() || 'U'}
            </div>
            <div>
              <p className="font-medium text-ink">{user?.username || 'User'}</p>
              <p className="text-sm text-muted capitalize">{user?.role || 'viewer'}</p>
            </div>
          </div>
        </div>
      </motion.div>

      <PasswordChangeForm isAdmin={false} />
      <MfaCard />

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="card p-6"
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="icon-box">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <h2 className="font-display text-lg font-semibold tracking-[-0.02em] text-ink">About OutisCloud</h2>
            <p className="text-sm text-muted">DNS management platform.</p>
          </div>
        </div>

        <div className="space-y-2 text-sm text-muted">
          <p><strong>Version:</strong> 1.0.0</p>
          <p><strong>Platform:</strong> OutisCloud DNS Control Panel</p>
          <p className="pt-2">Enterprise-grade DNS management with GeoDNS support.</p>
        </div>
      </motion.div>
    </div>
  );
}
