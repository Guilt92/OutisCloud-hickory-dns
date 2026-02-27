import React from 'react';
import { motion } from 'framer-motion';
import { Palette, User, Globe } from 'lucide-react';
import { useUIStore, useAuthStore } from '../store';
import PasswordChangeForm from '../components/PasswordChangeForm';

export default function UserSettings() {
  const { theme, setTheme } = useUIStore();
  const { user } = useAuthStore();

  return (
    <div className="space-y-6 max-w-4xl">
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Settings</h1>
        <p className="text-gray-500 dark:text-gray-400">Manage your account and preferences</p>
      </motion.div>

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
          <label className="block text-sm font-medium dark:text-gray- text-gray-700300">Theme</label>
          <div className="grid grid-cols-2 gap-3">
            <button
              onClick={() => setTheme('light')}
              className={`flex items-center gap-3 p-4 rounded-xl border-2 transition-all ${
                theme === 'light'
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                  : 'border-gray-200 dark:border-gray-600 hover:border-gray-300 dark:hover:border-gray-500'
              }`}
            >
              <svg className={`w-5 h-5 ${theme === 'light' ? 'text-primary-600 dark:text-primary-400' : 'text-gray-400'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
              </svg>
              <span className="font-medium text-gray-900 dark:text-white">Light</span>
            </button>
            <button
              onClick={() => setTheme('dark')}
              className={`flex items-center gap-3 p-4 rounded-xl border-2 transition-all ${
                theme === 'dark'
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                  : 'border-gray-200 dark:border-gray-600 hover:border-gray-300 dark:hover:border-gray-500'
              }`}
            >
              <svg className={`w-5 h-5 ${theme === 'dark' ? 'text-primary-600 dark:text-primary-400' : 'text-gray-400'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
              </svg>
              <span className="font-medium text-gray-900 dark:text-white">Dark</span>
            </button>
          </div>
        </div>
      </motion.div>

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

      <PasswordChangeForm isAdmin={false} />

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
