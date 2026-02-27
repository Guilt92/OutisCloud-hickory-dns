import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Lock, Eye, EyeOff, CheckCircle, AlertCircle, KeyRound } from 'lucide-react';
import { authApi } from '../api/client';

export default function PasswordChangeForm({ userId, isAdmin = false, onSuccess, onError }) {
  const [formData, setFormData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
    userIdForAdmin: userId || '',
  });
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);

  const validatePassword = (password) => {
    if (password.length < 8) {
      return 'Password must be at least 8 characters';
    }
    return null;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage(null);
    setError(null);

    const newPassError = validatePassword(formData.newPassword);
    if (newPassError) {
      setError(newPassError);
      return;
    }

    if (formData.newPassword !== formData.confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    setIsLoading(true);

    try {
      let response;
      if (isAdmin) {
        response = await authApi.adminResetPassword({
          user_id: formData.userIdForAdmin,
          new_password: formData.newPassword,
        });
      } else {
        response = await authApi.changePassword({
          current_password: formData.currentPassword,
          new_password: formData.newPassword,
        });
      }

      setMessage('Password changed successfully');
      setFormData({
        currentPassword: '',
        newPassword: '',
        confirmPassword: '',
        userIdForAdmin: userId || '',
      });

      if (onSuccess) {
        onSuccess(response.data);
      }
    } catch (err) {
      const errorMsg = err.response?.data?.error || err.response?.data?.details || 'Failed to change password';
      setError(errorMsg);
      if (onError) {
        onError(errorMsg);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const togglePassword = (field) => {
    setShowPasswords((prev) => ({ ...prev, [field]: !prev[field] }));
  };

  const PasswordInput = ({ field, label, value, onChange, placeholder, required = true, disabled = false }) => (
    <div className="relative">
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
        {label} {required && <span className="text-red-500">*</span>}
      </label>
      <div className="relative">
        <input
          type={showPasswords[field] ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          disabled={disabled}
          className="w-full px-4 py-2.5 pr-10 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-primary-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        />
        <button
          type="button"
          onClick={() => togglePassword(field)}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
          tabIndex={-1}
        >
          {showPasswords[field] ? (
            <EyeOff className="w-4 h-4" />
          ) : (
            <Eye className="w-4 h-4" />
          )}
        </button>
      </div>
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 p-6"
    >
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center">
          <KeyRound className="w-5 h-5 text-white" />
        </div>
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            {isAdmin ? 'Reset User Password' : 'Change Password'}
          </h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            {isAdmin ? 'Reset password for another user' : 'Update your account password'}
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {isAdmin && (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
              User ID <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={formData.userIdForAdmin}
              onChange={(e) => setFormData((prev) => ({ ...prev, userIdForAdmin: e.target.value }))}
              placeholder="Enter user ID"
              required
              className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors"
            />
          </div>
        )}

        {!isAdmin && (
          <PasswordInput
            field="current"
            label="Current Password"
            value={formData.currentPassword}
            onChange={(val) => setFormData((prev) => ({ ...prev, currentPassword: val }))}
            placeholder="Enter current password"
          />
        )}

        <PasswordInput
          field="new"
          label={isAdmin ? 'New Password' : 'New Password'}
          value={formData.newPassword}
          onChange={(val) => setFormData((prev) => ({ ...prev, newPassword: val }))}
          placeholder="Enter new password (min 8 characters)"
        />

        <PasswordInput
          field="confirm"
          label="Confirm New Password"
          value={formData.confirmPassword}
          onChange={(val) => setFormData((prev) => ({ ...prev, confirmPassword: val }))}
          placeholder="Confirm new password"
        />

        <AnimatePresence>
          {error && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="flex items-center gap-2 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800"
            >
              <AlertCircle className="w-4 h-4 text-red-500 flex-shrink-0" />
              <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
            </motion.div>
          )}
        </AnimatePresence>

        <AnimatePresence>
          {message && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="flex items-center gap-2 p-3 rounded-lg bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800"
            >
              <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />
              <p className="text-sm text-green-600 dark:text-green-400">{message}</p>
            </motion.div>
          )}
        </AnimatePresence>

        <button
          type="submit"
          disabled={isLoading}
          className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-primary-500 to-primary-600 text-white font-medium hover:from-primary-600 hover:to-primary-700 focus:ring-4 focus:ring-primary-300 dark:focus:ring-primary-800 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
        >
          {isLoading ? (
            <>
              <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              <span>Processing...</span>
            </>
          ) : (
            <>
              <Lock className="w-4 h-4" />
              <span>{isAdmin ? 'Reset Password' : 'Change Password'}</span>
            </>
          )}
        </button>
      </form>
    </motion.div>
  );
}
