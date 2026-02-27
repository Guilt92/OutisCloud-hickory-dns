import React, { useState } from 'react';
import { Search, Server, Loader2, Copy, Check, AlertCircle, Globe, Mail, FileText, Network, Zap } from 'lucide-react';
import { motion } from 'framer-motion';
import api from '../../api/client';

const recordTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'PTR', 'DNSKEY', 'DS', 'CAA'];

export default function DnsLookup() {
  const [domain, setDomain] = useState('');
  const [recordType, setRecordType] = useState('A');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);

  const performLookup = async () => {
    if (!domain.trim()) {
      setError('Please enter a domain name');
      return;
    }

    setLoading(true);
    setError('');
    setResults(null);

    try {
      const response = await api.post('/api/v1/dns/lookup', {
        domain: domain.trim(),
        record_type: recordType
      });
      setResults(response.data);
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'DNS lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const copyResults = () => {
    if (results) {
      navigator.clipboard.writeText(JSON.stringify(results, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getRecordIcon = (type) => {
    switch (type?.toUpperCase()) {
      case 'A': return Zap;
      case 'AAAA': return Zap;
      case 'MX': return Mail;
      case 'TXT': return FileText;
      case 'NS': return Globe;
      case 'CNAME': return Network;
      default: return Server;
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      performLookup();
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col md:flex-row md:items-center md:justify-between gap-4"
      >
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">DNS Lookup</h1>
          <p className="text-gray-500 dark:text-gray-400">Test DNS resolution for any domain</p>
        </div>
      </motion.div>

      {/* Search Form */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 p-6"
      >
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
              Domain Name
            </label>
            <div className="relative">
              <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="example.com"
                className="w-full pl-12 pr-4 py-3 border border-gray-200 dark:border-gray-600 rounded-xl dark:bg-gray-700 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-all"
              />
            </div>
          </div>
          
          <div className="md:w-40">
            <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
              Record Type
            </label>
            <select
              value={recordType}
              onChange={(e) => setRecordType(e.target.value)}
              className="w-full px-4 py-3 border border-gray-200 dark:border-gray-600 rounded-xl dark:bg-gray-700 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-all"
            >
              {recordTypes.map(type => (
                <option key={type} value={type}>{type}</option>
              ))}
            </select>
          </div>
          
          <div className="md:self-end">
            <button
              onClick={performLookup}
              disabled={loading}
              className="w-full md:w-auto px-6 py-3 bg-gradient-to-r from-primary-600 to-primary-700 hover:from-primary-700 hover:to-primary-800 text-white font-semibold rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  <span>Looking up...</span>
                </>
              ) : (
                <>
                  <Search className="w-5 h-5" />
                  <span>Lookup</span>
                </>
              )}
            </button>
          </div>
        </div>
      </motion.div>

      {/* Error Message */}
      {error && (
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="p-4 rounded-xl bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 flex items-start gap-3"
        >
          <AlertCircle className="w-5 h-5 text-red-500 mt-0.5 flex-shrink-0" />
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        </motion.div>
      )}

      {/* Results */}
      {results && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 overflow-hidden"
        >
          <div className="p-6 border-b border-gray-100 dark:border-gray-700 flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                DNS Results
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {domain} - {recordType} records
              </p>
            </div>
            <button
              onClick={copyResults}
              className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            >
              {copied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          
          <div className="p-6">
            {results.records && results.records.length > 0 ? (
              <div className="space-y-3">
                {results.records.map((record, index) => {
                  const Icon = getRecordIcon(record.type);
                  return (
                    <div 
                      key={index}
                      className="flex items-center gap-4 p-4 rounded-xl bg-gray-50 dark:bg-gray-700/50"
                    >
                      <div className="w-10 h-10 rounded-lg bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center flex-shrink-0">
                        <Icon className="w-5 h-5 text-primary-600 dark:text-primary-400" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-gray-900 dark:text-white">
                            {record.name}
                          </span>
                          <span className="px-2 py-0.5 text-xs font-medium bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300 rounded">
                            {record.type}
                          </span>
                          <span className="text-xs text-gray-500 dark:text-gray-400">
                            TTL: {record.ttl}
                          </span>
                        </div>
                        <p className="text-sm text-gray-600 dark:text-gray-300 font-mono truncate">
                          {record.value}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-8">
                <AlertCircle className="w-12 h-12 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
                <p className="text-gray-500 dark:text-gray-400">No {recordType} records found for {domain}</p>
              </div>
            )}
          </div>
        </motion.div>
      )}

      {/* Quick Examples */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-100 dark:border-gray-700 p-6"
      >
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Quick Examples</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {['google.com', 'cloudflare.com', 'github.com', 'example.com'].map((d) => (
            <button
              key={d}
              onClick={() => { setDomain(d); setRecordType('A'); }}
              className="px-4 py-2 text-sm font-medium text-gray-600 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 rounded-lg hover:bg-primary-100 dark:hover:bg-primary-900/30 hover:text-primary-700 dark:hover:text-primary-300 transition-colors"
            >
              {d}
            </button>
          ))}
        </div>
      </motion.div>
    </div>
  );
}
