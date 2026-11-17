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
      const d = err.response?.data;
      if (err.response?.status === 429) setError(d?.details || 'Too many lookups, please wait a moment.');
      else if (err.response?.status === 502) setError('The resolver did not answer: ' + (d?.details || 'unreachable') + '. This is a resolver problem, not an empty result.');
      else setError(d?.error || err.message || 'DNS lookup failed');
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
          <p className="eyebrow mb-1.5">DNS</p>
          <h1 className="section-title">DNS lookup</h1>
          <p className="section-desc">Real DNS queries over UDP/TCP with TTLs and response codes. Enter an IP address for a PTR (reverse) lookup.</p>
        </div>
      </motion.div>

      {/* Search Form */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="card p-6"
      >
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <label className="form-label" htmlFor="lookup-domain">
              Domain name
            </label>
            <div className="relative">
              <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
              <input
                id="lookup-domain"
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                onKeyDown={handleKeyPress}
                placeholder="example.com or 192.0.2.1"
                aria-label="Domain name or IP address"
                className="input pl-11 py-3"
              />
            </div>
          </div>
          
          <div className="md:w-40">
            <label className="form-label" htmlFor="lookup-type">
              Record type
            </label>
            <select
              id="lookup-type"
              value={recordType}
              aria-label="Record type"
              onChange={(e) => setRecordType(e.target.value)}
              className="select py-3"
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
              className="btn-primary w-full md:w-auto py-3"
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
          role="alert"
          className="p-4 rounded-[14px] bg-danger-500/[0.04] border border-danger-500/30 flex items-start gap-3"
        >
          <AlertCircle className="w-5 h-5 text-danger-500 mt-0.5 flex-shrink-0" />
          <p className="text-sm text-danger-600 dark:text-danger-400">{error}</p>
        </motion.div>
      )}

      {/* Results */}
      {results && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="card overflow-hidden"
        >
          <div className="p-6 border-b border-line flex items-center justify-between">
            <div>
              <h3 className="font-display text-lg font-semibold tracking-[-0.02em] text-ink">
                DNS results
              </h3>
              <p className="text-sm text-muted" data-testid="lookup-summary">
                {results.domain} · {results.record_type} · <span data-testid="lookup-status" className={results.status === 'NOERROR' ? 'text-success-500 font-semibold' : 'text-danger-500 font-semibold'}>{results.status}</span>
                {' '}· {results.elapsed_ms} ms via {results.transport?.toUpperCase()} from {results.resolver}{results.authoritative ? ' · authoritative' : ''}
              </p>
            </div>
            <button
              onClick={copyResults}
              className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-muted hover:bg-ink/5 rounded-[12px] transition-colors"
            >
              {copied ? <Check className="w-4 h-4 text-success-500" /> : <Copy className="w-4 h-4" />}
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
                      className="flex items-center gap-4 p-4 rounded-[14px] bg-surface-2"
                    >
                      <div className="icon-box">
                        <Icon className="w-[18px] h-[18px]" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-ink">
                            {record.name}
                          </span>
                          <span className="badge badge-info">{record.type}</span>
                          <span className="text-xs text-muted">
                            TTL: {record.ttl}
                          </span>
                        </div>
                        <p className="text-sm text-muted font-mono break-all" data-testid="lookup-value">
                          {record.value}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-8">
                <AlertCircle className="w-12 h-12 text-muted/40 mx-auto mb-3" />
                <p className="text-muted" data-testid="lookup-empty">{results.note || `No ${results.record_type} records found for ${results.domain}`}</p>
              </div>
            )}
            {results.authority?.length > 0 && (
              <div className="mt-4 pt-4 border-t border-line">
                <p className="text-xs uppercase tracking-wide text-muted mb-2">Authority (negative caching)</p>
                {results.authority.map((a, i) => (
                  <p key={i} className="text-xs font-mono text-muted break-all">{a.name} {a.ttl} {a.type} {a.value}</p>
                ))}
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
        className="card p-6"
      >
        <h3 className="font-display text-lg font-semibold tracking-[-0.02em] text-ink mb-4">Quick examples</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {['google.com', 'cloudflare.com', 'github.com', 'example.com'].map((d) => (
            <button
              key={d}
              onClick={() => { setDomain(d); setRecordType('A'); }}
              className="px-4 py-2 text-sm font-medium text-muted bg-surface-2 border border-line rounded-[12px] hover:text-ink hover:border-muted/40 transition-colors"
            >
              {d}
            </button>
          ))}
        </div>
      </motion.div>
    </div>
  );
}
