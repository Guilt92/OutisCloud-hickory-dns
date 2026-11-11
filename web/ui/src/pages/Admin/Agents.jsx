import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Server, 
  Plus, 
  Search, 
  RefreshCw, 
  Trash2, 
  Power,
  Activity,
  Clock,
  CheckCircle,
  XCircle,
  X
} from 'lucide-react';
import api from '../../api/client';
import { useConfirm } from '../../components/ui'
import Notifications from '../../components/Notifications'

const StatusBadge = ({ status, label }) => {
  const styles = {
    online: 'bg-success-100 text-success-700 dark:bg-success-900/30 dark:text-success-400',
    offline: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400',
    enabled: 'bg-primary-100 text-primary-700 dark:bg-primary-900/30 dark:text-primary-400',
    disabled: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400',
  };
  
  return (
    <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${styles[status] || styles.offline}`}>
      {label || status}
    </span>
  );
};

const AgentCard = ({ agent, onDelete, onToggle, onRotate, onSync, delay = 0 }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="card overflow-hidden hover:shadow-xl transition-shadow"
    >
      <div className="p-6">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
              agent.online ? 'bg-success-100 dark:bg-success-900/30' : 'bg-surface-2'
            }`}>
              <Server className={`w-6 h-6 ${agent.online ? 'text-success-600' : 'text-gray-400'}`} />
            </div>
            <div>
              <h3 className="font-semibold text-ink">{agent.name}</h3>
              <p className="text-sm text-muted font-mono">{agent.addr}</p>
            </div>
          </div>
          <StatusBadge status={!agent.enabled ? 'disabled' : agent.online ? 'online' : 'offline'} />
        </div>
        
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div className="bg-surface-2 rounded-xl p-3">
            <div className="flex items-center gap-2 text-xs text-muted mb-1">
              <Activity className="w-3 h-3" />
              Status
            </div>
            <p className={`font-semibold ${agent.online ? 'text-success-600' : 'text-gray-500'}`}>
              {agent.online ? 'Online' : 'Offline'}
            </p>
          </div>
          <div className="bg-surface-2 rounded-xl p-3">
            <div className="flex items-center gap-2 text-xs text-muted mb-1">
              <Clock className="w-3 h-3" />
              Last Heartbeat
            </div>
            <p className="font-semibold text-ink text-sm">
              {agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleString() : 'Never'}
            </p>
          </div>
        </div>
        
        <div className="bg-surface-2 rounded-xl p-3 mb-4 text-sm">
          <div className="flex items-center justify-between">
            <span className="text-muted">Configuration</span>
            <span className={`font-semibold ${agent.in_sync ? 'text-success-600' : 'text-warning-600'}`}>
              {agent.in_sync ? 'In sync' : 'Behind'} (v{agent.applied_version} / v{agent.desired_version})
            </span>
          </div>
          {agent.last_ack_at && <p className="text-xs text-gray-500 mt-1">Last acknowledgement {new Date(agent.last_ack_at).toLocaleString()}</p>}
          {agent.last_error && <p className="text-xs text-danger-600 mt-1">Last error: {agent.last_error}</p>}
          {agent.sync_requested && <p className="text-xs text-primary-600 mt-1">Sync requested - applied on the next heartbeat</p>}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => onSync(agent.id)}
            disabled={!agent.enabled}
            className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium text-ink/80 bg-surface-2 rounded-xl hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors disabled:opacity-50"
          >
            <RefreshCw className="w-4 h-4" />
            Sync now
          </button>
          <button
            onClick={() => onRotate(agent.id)}
            className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium text-ink/80 bg-surface-2 rounded-xl hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Rotate Token
          </button>
          <button
            onClick={() => onToggle(agent)}
            className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium rounded-xl transition-colors ${
              agent.enabled 
                ? 'text-danger-600 bg-danger-50 dark:bg-danger-900/20 hover:bg-danger-100 dark:hover:bg-danger-900/40'
                : 'text-success-600 bg-success-50 dark:bg-success-900/20 hover:bg-success-100 dark:hover:bg-success-900/40'
            }`}
          >
            <Power className="w-4 h-4" />
            {agent.enabled ? 'Disable' : 'Enable'}
          </button>
          <button
            onClick={() => onDelete(agent.id)}
            className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium text-danger-600 bg-danger-50 dark:bg-danger-900/20 rounded-xl hover:bg-danger-100 dark:hover:bg-danger-900/40 transition-colors"
          >
            <Trash2 className="w-4 h-4" />
            Delete
          </button>
        </div>
      </div>
    </motion.div>
  );
};

const CreateAgentModal = ({ isOpen, onClose, onCreate }) => {
  const [name, setName] = useState('');
  const [addr, setAddr] = useState('');
  const [loading, setLoading] = useState(false);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await onCreate({ name, addr });
      setName('');
      setAddr('');
      onClose();
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };
  
  if (!isOpen) return null;
  
  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50"
      onClick={onClose}
    >
      <motion.div 
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        className="card w-full max-w-md"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-6 border-b border-line">
          <h3 className="text-xl font-semibold text-ink">Register New Agent</h3>
          <button onClick={onClose} className="p-2 hover:bg-ink/5 rounded-xl">
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>
        
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink/80 mb-2">
              Agent Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., us-east-1-agent"
              className="w-full px-4 py-3 border border-line rounded-xl bg-white dark:bg-gray-700 text-ink focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              required
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-ink/80 mb-2">
              Agent Address
            </label>
            <input
              type="text"
              value={addr}
              onChange={(e) => setAddr(e.target.value)}
              placeholder="e.g., 192.168.1.100:5353"
              className="w-full px-4 py-3 border border-line rounded-xl bg-white dark:bg-gray-700 text-ink focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              required
            />
          </div>
          
          <div className="bg-primary-50 dark:bg-primary-900/20 rounded-xl p-4">
            <p className="text-sm text-primary-700 dark:text-primary-300">
              <strong>Note:</strong> The agent must be running and accessible at the provided address.
            </p>
          </div>
          
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-3 border border-line text-ink/80 rounded-xl font-medium hover:bg-ink/5 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 px-4 py-3 bg-primary-600 text-white rounded-xl font-medium hover:bg-primary-700 transition-colors disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-5 h-5 animate-spin mx-auto" /> : 'Register Agent'}
            </button>
          </div>
        </form>
      </motion.div>
    </motion.div>
  );
};

export default function Agents() {
  const askConfirm = useConfirm()
  const notify = React.useContext(Notifications)
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  
  const loadAgents = async () => {
    setLoading(true);
    try {
      const res = await api.get('/api/v1/agents');
      setAgents(res.data || []);
    } catch (e) {
      console.error('Failed to load agents:', e);
    }
    setLoading(false);
  };
  
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
    loadAgents();
  }, []);
  
  const [credentials, setCredentials] = useState(null);

  const handleCreate = async (data) => {
    try {
      const res = await api.post('/api/v1/agents/register', data);
      setCredentials({ title: 'Agent registered', ...res.data });
      await loadAgents();
    } catch (e) {
      console.error('Failed to register agent:', e);
      throw e;
    }
  };
  
  const handleDelete = async (id) => {
    if (!(await askConfirm({ title: 'Delete agent?', message: 'The agent stops receiving configuration. Its credentials are revoked.', confirmLabel: 'Delete agent' }))) return;
    try {
      await api.delete(`/api/v1/agents/${id}`);
      await loadAgents();
    } catch (e) {
      console.error('Failed to delete agent:', e);
    }
  };
  
  const handleToggle = async (agent) => {
    try {
      await api.put(`/api/v1/agents/${agent.id}`, { enabled: !agent.enabled });
      await loadAgents();
    } catch (e) {
      notify?.error('Failed to change agent state: ' + (e.response?.data?.error || e.message));
    }
  };

  const handleSync = async (id) => {
    try {
      await api.post('/api/v1/config/push', { agent_id: id, zone_id: '', zone_config: {} });
      await loadAgents();
    } catch (e) {
      notify?.error('Sync request failed: ' + (e.response?.data?.message || e.response?.data?.error || e.message));
    }
  };
  
  const handleRotateToken = async (id) => {
    try {
      const res = await api.post(`/api/v1/agents/${id}/token/rotate`);
      setCredentials({ title: 'Token rotated', id, ...res.data });
      await loadAgents();
    } catch (e) {
      console.error('Failed to rotate token:', e);
    }
  };
  
  const filteredAgents = agents.filter(agent => 
    agent.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    agent.addr?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    agent.id?.toLowerCase().includes(searchTerm.toLowerCase())
  );
  
  const onlineCount = agents.filter(a => a.online).length;
  const offlineCount = agents.length - onlineCount;
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col md:flex-row md:items-center md:justify-between gap-4"
      >
        <div>
          <h1 className="text-2xl font-bold text-ink">Agents</h1>
          <p className="text-muted">Manage DNS agents and remote nodes</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={loadAgents}
            className="flex items-center gap-2 px-4 py-2 card rounded-xl text-sm font-medium text-ink/80 hover:bg-ink/5 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button 
            onClick={() => setModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-xl text-sm font-medium hover:bg-primary-700 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Register Agent
          </button>
        </div>
      </motion.div>
      
      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="card p-6"
        >
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center">
              <Server className="w-6 h-6 text-primary-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-ink">{agents.length}</p>
              <p className="text-sm text-muted">Total Agents</p>
            </div>
          </div>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="card p-6"
        >
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-success-100 dark:bg-success-900/30 flex items-center justify-center">
              <CheckCircle className="w-6 h-6 text-success-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-ink">{onlineCount}</p>
              <p className="text-sm text-muted">Online</p>
            </div>
          </div>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="card p-6"
        >
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-surface-2 flex items-center justify-center">
              <XCircle className="w-6 h-6 text-gray-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-ink">{offlineCount}</p>
              <p className="text-sm text-muted">Offline</p>
            </div>
          </div>
        </motion.div>
      </div>
      
      {/* Search */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="relative"
      >
        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
        <input
          type="text"
          placeholder="Search agents by name, address, or ID..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full pl-12 pr-4 py-3 border border-line rounded-xl bg-surface text-ink focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
        />
      </motion.div>
      
      {/* Agent Grid */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[1, 2, 3].map(i => (
            <div key={i} className="card h-48 animate-pulse" />
          ))}
        </div>
      ) : filteredAgents.length === 0 ? (
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="card p-12 text-center"
        >
          <Server className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-ink mb-2">No Agents Found</h3>
          <p className="text-muted mb-6">
            {searchTerm ? 'Try adjusting your search' : 'Register your first agent to get started'}
          </p>
          {!searchTerm && (
            <button 
              onClick={() => setModalOpen(true)}
              className="inline-flex items-center gap-2 px-6 py-3 bg-primary-600 text-white rounded-xl font-medium hover:bg-primary-700 transition-colors"
            >
              <Plus className="w-5 h-5" />
              Register Agent
            </button>
          )}
        </motion.div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredAgents.map((agent, index) => (
            <AgentCard
              key={agent.id}
              agent={agent}
              onDelete={handleDelete}
              onToggle={handleToggle}
              onSync={handleSync}
              onRotate={handleRotateToken}
              delay={0.1 + index * 0.05}
            />
          ))}
        </div>
      )}
      
      {/* Create Modal */}
      {credentials && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-xl p-6 space-y-3">
            <h3 className="text-lg font-bold text-ink">{credentials.title}</h3>
            <p className="text-sm text-amber-600">These values are shown once. Store them in the agent's environment now.</p>
            <pre className="bg-gray-50 dark:bg-gray-900 p-3 rounded-lg text-xs overflow-x-auto select-all">{`AGENT_ID=${credentials.id}
AGENT_TOKEN=${credentials.token}
AGENT_SIGNING_KEY=${credentials.signing_key}`}</pre>
            <button className="btn-primary" onClick={() => setCredentials(null)}>I have saved them</button>
          </div>
        </div>
      )}
      <CreateAgentModal 
        isOpen={modalOpen} 
        onClose={() => setModalOpen(false)} 
        onCreate={handleCreate}
      />
    </div>
  );
}
