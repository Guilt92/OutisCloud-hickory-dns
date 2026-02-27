import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Globe, Settings as SettingsIcon } from 'lucide-react';
import ZonesComponent from './Admin/Zones';
import UserSettings from './UserSettings';

export default function User() {
  const [activeTab, setActiveTab] = useState('zones');

  const tabs = [
    { id: 'zones', label: 'My Zones', icon: Globe },
    { id: 'settings', label: 'Settings', icon: SettingsIcon },
  ];

  return (
    <div className="max-w-6xl mx-auto">
      <div className="mb-6">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white">User Panel</h2>
        <p className="text-gray-600 dark:text-gray-400">View your DNS zones and manage settings</p>
      </div>

      <div className="flex gap-2 mb-6">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-primary-500 text-white'
                  : 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700'
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {activeTab === 'zones' && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <ZonesComponent />
        </motion.div>
      )}

      {activeTab === 'settings' && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <UserSettings />
        </motion.div>
      )}
    </div>
  );
}
