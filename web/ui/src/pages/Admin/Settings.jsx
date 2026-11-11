import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Moon, Sun, Monitor, Palette, User, Bell, Shield, Globe } from 'lucide-react';
import { useUIStore, useAuthStore } from '../../store';
import PasswordChangeForm from '../../components/PasswordChangeForm';
import MfaCard from '../../components/MfaCard';

const themes = [
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'dark', label: 'Dark', icon: Moon },
];

export default function Settings() {
  const { theme, setTheme } = useUIStore();
  const { user } = useAuthStore();
  const [saved, setSaved] = useState(false);

  const handleThemeChange = (newTheme) => {
    setTheme(newTheme);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-2xl font-bold text-ink">Settings</h1>
        <p className="text-muted">Manage your account and preferences</p>
      </motion.div>

      {/* Appearance */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="card p-6"
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="icon-box">
            <Palette className="w-5 h-5 text-white" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-ink">Appearance</h2>
            <p className="text-sm text-muted">Customize the look and feel</p>
          </div>
        </div>

        <div className="space-y-4">
          <label className="block text-sm font-medium text-ink/80">Theme</label>
          <div className="grid grid-cols-2 gap-3">
            {themes.map((t) => {
              const Icon = t.icon;
              return (
                <button
                  key={t.value}
                  onClick={() => handleThemeChange(t.value)}
                  className={`flex items-center gap-3 p-4 rounded-xl border-2 transition-all ${
                    theme === t.value
                      ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                      : 'border-line hover:border-gray-300 dark:hover:border-gray-500'
                  }`}
                >
                  <Icon className={`w-5 h-5 ${theme === t.value ? 'text-primary-600 dark:text-primary-400' : 'text-gray-400'}`} />
                  <span className="font-medium text-ink">{t.label}</span>
                </button>
              );
            })}
          </div>
          {saved && (
            <motion.p 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-sm text-green-600 dark:text-green-400"
            >
              ✓ Settings saved
            </motion.p>
          )}
        </div>
      </motion.div>

      {/* Profile */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="card p-6"
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="icon-box">
            <User className="w-5 h-5 text-white" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-ink">Profile</h2>
            <p className="text-sm text-muted">Your account information</p>
          </div>
        </div>

        <div className="space-y-4">
          <div className="flex items-center gap-4 p-4 rounded-xl bg-surface-2">
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

      {/* Change Password */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.25 }}
      >
        <PasswordChangeForm isAdmin={false} />
        <MfaCard />
      </motion.div>

      {/* Admin Reset Password - Only for admins */}
      {user?.role === 'admin' && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <PasswordChangeForm isAdmin={true} />
        </motion.div>
      )}

      {/* About */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="card p-6"
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="icon-box">
            <Globe className="w-5 h-5 text-white" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-ink">About OutisCloud</h2>
            <p className="text-sm text-muted">DNS Management Platform</p>
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
