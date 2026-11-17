import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Server, 
  Plus, 
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
import { PageHeader, StatCard, useConfirm } from '../../components/ui'
import SearchInput from '../../components/SearchInput'
import Notifications from '../../components/Notifications'

const StatusBadge = ({ status, label }) => {
  const styles = {
    online: 'badge badge-success',
    offline: 'badge badge-default',
    enabled: 'badge badge-info',
    disabled: 'badge badge-default',
  };
  
  return (
    <span className={styles[status] || styles.offline}>
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
      className="card overflow-hidden transition-colors hover:border-muted/40"
    >
      <div className="p-6">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-4">
            <div className="icon-box">
              <Server className={`w-5 h-5 ${agent.online ? 'text-success-600' : ''}`} />
            </div>
            <div>
              <h3 className="font-semibold text-ink">{agent.name}</h3>
              <p className="text-sm text-muted font-mono">{agent.addr}</p>
            </div>
          </div>
          <StatusBadge status={!agent.enabled ? 'disabled' : agent.online ? 'online' : 'offline'} />
        </div>
        
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div className="bg-surface-2 rounded-[18px] p-3">
            <div className="flex items-center gap-2 text-xs text-muted mb-1">
              <Activity className="w-3 h-3" />
              Status
            </div>
            <p className={`font-semibold ${agent.online ? 'text-success-600' : 'text-muted'}`}>
              {agent.online ? 'Online' : 'Offline'}
            </p>
          </div>
          <div className="bg-surface-2 rounded-[18px] p-3">
            <div className="flex items-center gap-2 text-xs text-muted mb-1">
              <Clock className="w-3 h-3" />
              Last Heartbeat
            </div>
            <p className="font-semibold text-ink text-sm">
              {agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleString() : 'Never'}
            </p>
          </div>
        </div>
        
        <div className="bg-surface-2 rounded-[18px] p-3 mb-4 text-sm">
          <div className="flex items-center justify-between">
            <span className="text-muted">Configuration</span>
            <span className={`font-semibold ${agent.in_sync ? 'text-success-600' : 'text-warning-700 dark:text-warning-400'}`}>
              {agent.in_sync ? 'In sync' : 'Behind'} (v{agent.applied_version} / v{agent.desired_version})
            </span>
          </div>
          {agent.last_ack_at && <p className="text-xs text-muted mt-1">Last acknowledgement {new Date(agent.last_ack_at).toLocaleString()}</p>}
          {agent.last_error && <p className="text-xs text-danger-600 mt-1">Last error: {agent.last_error}</p>}
          {agent.sync_requested && <p className="text-xs text-muted mt-1">Sync requested — applied on the next heartbeat</p>}
        </div>

        <div className="grid grid-cols-2 gap-2">
          <button onClick={() => onSync(agent.id)} disabled={!agent.enabled} className="btn-secondary btn-sm justify-center">
            <RefreshCw className="w-3.5 h-3.5" />
            Sync now
          </button>
          <button onClick={() => onRotate(agent.id)} className="btn-secondary btn-sm justify-center">
            <RefreshCw className="w-3.5 h-3.5" />
            Rotate token
          </button>
          <button onClick={() => onToggle(agent)} className={`btn btn-sm justify-center border ${agent.enabled ? 'text-danger-600 dark:text-danger-400 border-danger-500/25 hover:bg-danger-500/[0.06]' : 'text-ink border-line hover:bg-surface-2'}`}>
            <Power className="w-3.5 h-3.5" />
            {agent.enabled ? 'Disable' : 'Enable'}
          </button>
          <button onClick={() => onDelete(agent.id)} className="btn btn-sm justify-center text-danger-600 dark:text-danger-400 border border-danger-500/25 hover:bg-danger-500/[0.06]">
            <Trash2 className="w-3.5 h-3.5" />
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
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/45 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div 
        role="dialog" aria-modal="true" aria-label="Register agent"
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        className="card shadow-pop w-full max-w-md"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-5 border-b border-line">
          <h3 className="font-display text-lg font-semibold tracking-[-0.02em] text-ink">Register new agent</h3>
          <button onClick={onClose} className="btn-icon" aria-label="Close dialog">
            <X className="w-5 h-5" />
          </button>
        </div>
        
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="form-label" htmlFor="agent-name">
              Agent name
            </label>
            <input
              id="agent-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., us-east-1-agent"
              className="input"
              required
            />
          </div>
          
          <div>
            <label className="form-label" htmlFor="agent-addr">
              Agent address
            </label>
            <input
              id="agent-addr"
              type="text"
              value={addr}
              onChange={(e) => setAddr(e.target.value)}
              placeholder="e.g., 192.168.1.100:5353"
              className="input"
              required
            />
          </div>
          
          <div className="bg-surface-2 border border-line rounded-[14px] p-4">
            <p className="text-sm text-muted">
              The agent must be running and accessible at the provided address.
            </p>
          </div>
          
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="btn-secondary flex-1">Cancel</button>
            <button type="submit" disabled={loading} className="btn-primary flex-1">
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : 'Register agent'}
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
      <PageHeader eyebrow="Infrastructure" title="Agents" description="Manage DNS agents and remote nodes." icon={Server}
        actions={<>
          <button onClick={loadAgents} className="btn-secondary"><RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />Refresh</button>
          <button onClick={() => setModalOpen(true)} className="btn-primary"><Plus className="w-4 h-4" />Register agent</button>
        </>} />
      
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard icon={Server} label="Total agents" value={agents.length} />
        <StatCard icon={CheckCircle} label="Online" value={onlineCount} tone={onlineCount > 0 ? 'ok' : 'neutral'} />
        <StatCard icon={XCircle} label="Offline" value={offlineCount} tone={offlineCount > 0 ? 'warn' : 'neutral'} />
      </div>
      
      <SearchInput value={searchTerm} onChange={setSearchTerm} placeholder="Search agents by name, address, or ID…" label="Search agents" />
      
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
          <Server className="w-16 h-16 text-muted/40 mx-auto mb-4" />
          <h3 className="font-display text-xl font-semibold tracking-[-0.02em] text-ink mb-2">No agents found</h3>
          <p className="text-muted mb-6">
            {searchTerm ? 'Try adjusting your search.' : 'Register your first agent to get started.'}
          </p>
          {!searchTerm && (
            <button onClick={() => setModalOpen(true)} className="btn-primary mx-auto">
              <Plus className="w-4 h-4" />
              Register agent
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
        <div className="fixed inset-0 bg-black/45 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div role="dialog" aria-modal="true" aria-label={credentials.title} className="card shadow-pop w-full max-w-xl p-6 space-y-3">
            <h3 className="font-display text-lg font-semibold tracking-[-0.02em] text-ink">{credentials.title}</h3>
            <p className="text-sm text-warning-700 dark:text-warning-400">These values are shown once. Store them in the agent&apos;s environment now.</p>
            <pre className="bg-surface-2 border border-line p-3 rounded-[14px] text-xs overflow-x-auto select-all font-mono">{`AGENT_ID=${credentials.id}
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
