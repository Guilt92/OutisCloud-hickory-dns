import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Moon, Sun, Monitor, Palette, User, Bell, Shield, Globe } from 'lucide-react';
import { useUIStore, useAuthStore } from '../../store';
import PasswordChangeForm from '../../components/PasswordChangeForm';

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
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Settings</h1>
        <p className="text-gray-500 dark:text-gray-400">Manage your account and preferences</p>
      </motion.div>

      {/* Appearance */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 p-6"
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-primary-600 flex items-center justify-center">
            <Palette className="w-5 h-5 text-white" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Appearance</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">Customize the look and feel</p>
          </div>
        </div>

        <div className="space-y-4">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Theme</label>
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
                      : 'border-gray-200 dark:border-gray-600 hover:border-gray-300 dark:hover:border-gray-500'
                  }`}
                >
                  <Icon className={`w-5 h-5 ${theme === t.value ? 'text-primary-600 dark:text-primary-400' : 'text-gray-400'}`} />
                  <span className="font-medium text-gray-900 dark:text-white">{t.label}</span>
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
        className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 p-6"
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-purple-600 flex items-center justify-center">
            <User className="w-5 h-5 text-white" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Profile</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">Your account information</p>
          </div>
        </div>

        <div className="space-y-4">
          <div className="flex items-center gap-4 p-4 rounded-xl bg-gray-50 dark:bg-gray-700/50">
            <div className="w-12 h-12 rounded-full bg-gradient-to-br from-primary-500 to-primary-600 flex items-center justify-center text-white text-xl font-bold">
              {user?.username?.charAt(0).toUpperCase() || 'U'}
            </div>
            <div>
              <p className="font-medium text-gray-900 dark:text-white">{user?.username || 'User'}</p>
              <p className="text-sm text-gray-500 dark:text-gray-400 capitalize">{user?.role || 'viewer'}</p>
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
        className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 p-6"
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center">
            <Globe className="w-5 h-5 text-white" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">About OutisCloud</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">DNS Management Platform</p>
          </div>
        </div>

        <div className="space-y-2 text-sm text-gray-600 dark:text-gray-300">
          <p><strong>Version:</strong> 1.0.0</p>
          <p><strong>Platform:</strong> OutisCloud DNS Control Panel</p>
          <p className="pt-2">Enterprise-grade DNS management with GeoDNS support.</p>
        </div>
      </motion.div>
    </div>
  );
}
