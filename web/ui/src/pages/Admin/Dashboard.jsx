import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Globe, FileText, Server, Radio, Users, RefreshCw, ArrowRight, Activity, AlertTriangle, CheckCircle2, BarChart3 } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import api from '../../api/client';
import { useUIStore } from '../../store';
import { StatCard, StatusBadge, EmptyState, FlowArt } from '../../components/ui';

const total = (res) => {
  const h = Number(res?.headers?.['x-total-count']);
  return Number.isFinite(h) ? h : (Array.isArray(res?.data) ? res.data.length : 0);
};

// All numbers on this page come from the API. Anything that is unavailable is shown as such, never invented.
export default function Dashboard() {
  const [data, setData] = useState({ loading: true });
  const theme = useUIStore((s) => s.theme);

  const load = useCallback(async () => {
    const ok = (p) => p.catch(() => null);
    const [overview, servers, agents, users, pub, queries, audit] = await Promise.all([
      ok(api.get('/api/v1/overview', { params: { limit: 0 } })),   // ONE aggregated, tenant-scoped request (no per-zone calls)
      ok(api.get('/api/v1/servers')),
      ok(api.get('/api/v1/agents')),
      ok(api.get('/api/v1/users', { params: { limit: 1 } })),
      ok(api.get('/api/v1/dns/status')),
      api.get('/api/v1/metrics/queries').then((r) => ({ state: 'ok', ...r.data })).catch((e) => ({ state: e.response?.status === 503 ? 'unconfigured' : 'error' })),
      ok(api.get('/api/v1/audit/logs', { params: { limit: 8 } })),
    ]);
    const ov = overview?.data;
    setData({
      loading: false,
      zones: ov ? ov.zones_total : null, pendingZones: ov ? ov.zones_pending : 0, records: ov ? ov.records_total : null,
      servers: servers?.data || [], agents: agents?.data || [], users: users ? total(users) : null,
      pub: pub?.data || null, queries, audit: audit?.data || [],
    });
  }, []);

  useEffect(() => {
    const t = localStorage.getItem('token'); if (t) api.setToken(t);
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, [load]);

  const d = data;
  const enabledAgents = (d.agents || []).filter((a) => a.enabled);
  const behind = enabledAgents.filter((a) => !a.in_sync);
  const serversUp = (d.servers || []).filter((s) => s.status === 'running').length;
  const pending = d.pendingZones || 0;
  const failedZones = d.pub?.last_publish?.failed || [];
  const publishFailed = d.pub?.last_publish && !d.pub.last_publish.ok;

  const attention = [];
  if (publishFailed) attention.push({ tone: 'bad', text: `Last publication failed${d.pub.last_publish.error ? `: ${d.pub.last_publish.error}` : ''}`, to: '/admin/zones' });
  failedZones.forEach((f) => attention.push({ tone: 'bad', text: `Zone ${f.zone} was not published: ${f.error}`, to: '/admin/zones' }));
  if (behind.length) attention.push({ tone: 'warn', text: `${behind.length} agent${behind.length > 1 ? 's' : ''} behind the published configuration`, to: '/admin/agents' });
  if ((d.servers || []).length && serversUp < d.servers.length) attention.push({ tone: 'warn', text: `${d.servers.length - serversUp} DNS server${d.servers.length - serversUp > 1 ? 's' : ''} not responding`, to: '/admin/servers' });
  if (pending) attention.push({ tone: 'warn', text: `${pending} zone${pending > 1 ? 's' : ''} waiting for domain verification`, to: '/admin/zones' });

  const grid = theme === 'dark' ? '#2a2a2a' : '#e5e5e5';
  const tick = theme === 'dark' ? '#a3a3a3' : '#737373';
  const chartInk = theme === 'dark' ? '#fafafa' : '#0a0a0a';
  const chartSoft = theme === 'dark' ? '#737373' : '#a3a3a3';
  const chartFaint = theme === 'dark' ? '#404040' : '#d4d4d4';
  const tooltip = { background: theme === 'dark' ? '#171717' : '#ffffff', border: `1px solid ${grid}`, borderRadius: 12, fontSize: 12, color: chartInk };
  const agentBars = [
    { name: 'In sync', value: enabledAgents.length - behind.length, fill: chartInk },
    { name: 'Behind', value: behind.length, fill: chartSoft },
    { name: 'Disabled', value: (d.agents || []).length - enabledAgents.length, fill: chartFaint },
  ];
  const counters = d.queries?.state === 'ok' ? Object.entries(d.queries.counters || {}).map(([k, v]) => ({ name: k.replace(/^hickory_/, '').replace(/_total$/, ''), value: v })).sort((a, b) => b.value - a.value).slice(0, 6) : [];

  return (
    <div className="page" data-testid="admin-overview">
      <div className="relative overflow-hidden rounded-[24px] border border-line bg-surface p-6 sm:p-8">
        <FlowArt className="absolute inset-0 w-full h-full text-ink/[0.055]" />
        <div className="relative max-w-2xl">
          <p className="eyebrow mb-2">Operations</p>
          <h1 className="font-display text-[30px] sm:text-[36px] leading-[1.08] font-semibold tracking-[-0.035em] text-ink">DNS infrastructure overview</h1>
          <p className="text-muted mt-2">Live state of publication, servers, agents and query traffic.</p>
          <div className="mt-5 flex flex-wrap gap-2">
            <Link to="/admin/zones" className="btn-primary">Manage zones <ArrowRight className="w-4 h-4" /></Link>
            <button onClick={load} className="btn-secondary" disabled={d.loading}><RefreshCw className={`w-4 h-4 ${d.loading ? 'animate-spin' : ''}`} />Refresh</button>
          </div>
        </div>
      </div>

      {/* needs attention */}
      <section aria-label="Needs attention">
        {attention.length === 0 && !d.loading ? (
          <div className="card px-5 py-3.5 flex items-center gap-3 text-sm"><CheckCircle2 className="w-4 h-4 text-success-500" /><span className="text-ink">Everything is published and in sync.</span></div>
        ) : (
          <div className="card divide-y divide-line">
            {attention.map((a, i) => (
              <Link key={i} to={a.to} className="flex items-center gap-3 px-5 py-3 text-sm hover:bg-ink/[0.03]">
                <AlertTriangle className={`w-4 h-4 ${a.tone === 'bad' ? 'text-danger-500' : 'text-warning-500'}`} />
                <span className="flex-1 text-ink">{a.text}</span><ArrowRight className="w-4 h-4 text-muted" />
              </Link>
            ))}
          </div>
        )}
      </section>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard icon={Globe} label="Zones" value={d.zones ?? '—'} hint={pending ? `${pending} pending verification` : 'all active'} to="/admin/zones" loading={d.loading} />
        <StatCard icon={FileText} label="Records" value={d.records ?? '—'} hint="across all zones" loading={d.loading} />
        <StatCard icon={Server} label="DNS servers" value={`${serversUp}/${(d.servers || []).length}`} tone={(d.servers || []).length === 0 ? 'neutral' : serversUp === d.servers.length ? 'ok' : 'warn'} hint="responding" to="/admin/servers" loading={d.loading} />
        <StatCard icon={Radio} label="Agents" value={`${enabledAgents.length - behind.length}/${enabledAgents.length}`} tone={enabledAgents.length === 0 ? 'neutral' : behind.length ? 'warn' : 'ok'} hint="in sync" to="/admin/agents" loading={d.loading} />
        <StatCard icon={Users} label="Users" value={d.users ?? '—'} to="/admin/users" loading={d.loading} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* publication + servers */}
        <div className="card xl:col-span-2">
          <div className="px-5 py-4 border-b border-line flex items-center justify-between">
            <h2 className="panel-title">Publication & servers</h2>
            <Link to="/admin/servers" className="text-xs text-muted hover:text-ink hover:underline">All servers</Link>
          </div>
          <div className="p-5 grid sm:grid-cols-3 gap-4 border-b border-line text-sm">
            <div><p className="text-xs text-muted">Last publication</p>
              <p className="mt-1 text-ink flex items-center gap-2">{d.pub?.last_publish ? <><span className={d.pub.last_publish.ok ? 'dot-ok' : 'dot-bad'} />{d.pub.last_publish.ok ? `${d.pub.last_publish.published} zone(s)` : 'Failed'}</> : (d.pub ? 'none since start' : '—')}</p>
              {d.pub?.last_publish && <p className="text-xs text-muted mt-0.5">{new Date(d.pub.last_publish.at).toLocaleString()}</p>}</div>
            <div><p className="text-xs text-muted">Configuration version</p><p className="mt-1 text-ink font-mono">{d.pub ? `v${d.pub.bundle_version}` : '—'}</p></div>
            <div><p className="text-xs text-muted">Database connections</p><p className="mt-1 text-ink font-mono">{d.pub ? `${d.pub.db_connections.healthy}/${d.pub.db_connections.size}` : '—'}</p></div>
          </div>
          <ul className="divide-y divide-line">
            {(d.servers || []).length === 0 && !d.loading && <li><EmptyState icon={Server} title="No DNS servers registered" description="Register the DNS servers that serve your zones to monitor them here." action={<Link to="/admin/servers" className="btn-primary btn-sm">Add a server</Link>} /></li>}
            {(d.servers || []).map((s) => (
              <li key={s.id} className="flex items-center gap-3 px-5 py-3 text-sm">
                <span className={s.status === 'running' ? 'dot-ok' : 'dot-bad'} />
                <span className="font-medium text-ink">{s.name}</span>
                <span className="text-muted font-mono text-xs">{s.address}{s.port ? `:${s.port}` : ''}</span>
                <span className="flex-1" />
                {s.region && <span className="badge-default">{s.region}</span>}
                <StatusBadge status={s.status === 'running' ? 'online' : 'offline'} />
              </li>
            ))}
          </ul>
        </div>

        {/* agents chart */}
        <div className="card">
          <div className="px-5 py-4 border-b border-line flex items-center justify-between"><h2 className="panel-title">Agent synchronisation</h2><Link to="/admin/agents" className="text-xs text-muted hover:text-ink hover:underline">Agents</Link></div>
          <div className="p-5">
            {(d.agents || []).length === 0 ? <EmptyState icon={Radio} title="No agents" description="Agents replicate your zones to remote DNS servers." /> : (
              <div className="h-48" role="img" aria-label="Agents by synchronisation state">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={agentBars} layout="vertical" margin={{ left: 8, right: 16 }}>
                    <XAxis type="number" allowDecimals={false} tick={{ fill: tick, fontSize: 11 }} stroke={grid} />
                    <YAxis type="category" dataKey="name" width={64} tick={{ fill: tick, fontSize: 12 }} stroke={grid} />
                    <Tooltip cursor={{ fill: 'rgba(128,128,128,0.08)' }} contentStyle={tooltip} />
                    <Bar dataKey="value" radius={[0, 4, 4, 0]}>{agentBars.map((b) => <Cell key={b.name} fill={b.fill} />)}</Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="card xl:col-span-2">
          <div className="px-5 py-4 border-b border-line flex items-center justify-between"><h2 className="panel-title">Query traffic</h2><Link to="/admin/metrics" className="text-xs text-muted hover:text-ink hover:underline">Analytics</Link></div>
          <div className="p-5">
            {d.queries?.state === 'ok' ? (
              <>
                <p className="font-display text-3xl font-semibold tabular-nums text-ink">{Number(d.queries.requests_total).toLocaleString()}</p>
                <p className="text-xs text-muted mb-3">requests answered since the DNS server started</p>
                {counters.length > 0 && (
                  <div className="h-44"><ResponsiveContainer width="100%" height="100%">
                    <BarChart data={counters} margin={{ left: 0, right: 8 }}>
                      <XAxis dataKey="name" tick={{ fill: tick, fontSize: 10 }} stroke={grid} interval={0} />
                      <YAxis tick={{ fill: tick, fontSize: 11 }} stroke={grid} width={48} />
                      <Tooltip cursor={{ fill: 'rgba(128,128,128,0.08)' }} contentStyle={tooltip} />
                      <Bar dataKey="value" fill={chartInk} radius={[4, 4, 0, 0]} />
                    </BarChart></ResponsiveContainer></div>
                )}
              </>
            ) : d.queries?.state === 'unconfigured' ? (
              <EmptyState icon={BarChart3} title="Query statistics are not configured" description="Set DNS_METRICS_URL on the control API to the DNS server's Prometheus endpoint to see live query counters." />
            ) : (
              <EmptyState icon={BarChart3} title="Query statistics unavailable" description="The DNS server's metrics endpoint could not be reached." />
            )}
          </div>
        </div>

        <div className="card">
          <div className="px-5 py-4 border-b border-line flex items-center justify-between"><h2 className="panel-title">Recent activity</h2><Link to="/admin/audit" className="text-xs text-muted hover:text-ink hover:underline">Audit log</Link></div>
          <ul className="divide-y divide-line">
            {(d.audit || []).length === 0 && <li><EmptyState icon={Activity} title="No activity yet" /></li>}
            {(d.audit || []).map((a) => (
              <li key={a.id} className="px-5 py-3 text-sm">
                <p className="text-ink font-medium truncate">{String(a.action).replace(/_/g, ' ')}</p>
                <p className="text-xs text-muted">{a.resource_type}{a.ip_address ? ` · ${a.ip_address}` : ''} · {new Date(a.created_at).toLocaleString()}</p>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
