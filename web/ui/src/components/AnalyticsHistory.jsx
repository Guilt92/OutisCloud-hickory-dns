import React, { useEffect, useState, useCallback } from 'react';
import { BarChart3 } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import api from '../api/client';
import { useUIStore } from '../store';
import { EmptyState, ErrorState, StatCard } from './ui';

export const RANGES = [['1h', 'Last hour'], ['6h', '6 hours'], ['24h', '24 hours'], ['7d', '7 days'], ['30d', '30 days'], ['90d', '90 days']];

const fmtTs = (ts, range) => {
  const d = new Date(ts);
  return ['7d', '30d', '90d'].includes(range) ? d.toLocaleDateString([], { month: 'short', day: 'numeric' }) : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

// Persisted query history. scope="admin": global request totals + per-tenant drill-down.
// scope="tenant": the signed-in customer's own tenant only (the API enforces this).
export default function AnalyticsHistory({ scope }) {
  const theme = useUIStore((s) => s.theme);
  const [range, setRange] = useState('24h');
  const [tenant, setTenant] = useState('');
  const [zone, setZone] = useState('');
  const [tenants, setTenants] = useState([]);
  const [state, setState] = useState({ phase: 'loading' });

  useEffect(() => {
    const t = localStorage.getItem('token'); if (t) api.setToken(t);
    if (scope === 'admin') api.get('/api/v1/tenants').then((r) => setTenants(r.data || [])).catch(() => {});
  }, [scope]);

  const load = useCallback(async () => {
    try {
      const params = { range };
      if (tenant) params.tenant_id = tenant;
      if (zone) params.zone = zone;
      const [tn, gl] = await Promise.all([
        api.get('/api/v1/analytics/tenant', { params }),
        scope === 'admin' ? api.get('/api/v1/analytics/global', { params: { range } }) : Promise.resolve(null),
      ]);
      setState({ phase: 'ok', tn: tn.data, gl: gl?.data });
    } catch (e) {
      setState({ phase: 'error', message: e.response?.data?.error || e.message });
    }
  }, [range, tenant, zone, scope]);

  useEffect(() => { setState((s) => (s.phase === 'ok' ? s : { phase: 'loading' })); load(); const id = setInterval(load, 60000); return () => clearInterval(id); }, [load]);

  const grid = theme === 'dark' ? '#232836' : '#E2E2DA';
  const tick = theme === 'dark' ? '#9AA3B5' : '#5F6677';
  const tipItem = { color: theme === 'dark' ? '#E6E8EE' : '#14161C' };
  const tip = { background: theme === 'dark' ? '#181C25' : '#fff', border: `1px solid ${grid}`, borderRadius: 8, fontSize: 12 };
  const tn = state.tn; const gl = state.gl;
  const rows = (tn?.series || []).map((p) => ({ t: fmtTs(p.ts, range), queries: p.queries, failed: p.failed }));
  const globalRows = (gl?.series || []).map((p) => ({ t: fmtTs(p.ts, range), requests: p.requests }));
  const usage = (tn?.usage || []).map((p) => ({ t: fmtTs(p.ts, range), zones: p.zones, records: p.records }));
  const hasZoneData = (tn?.zones || []).length > 0;

  return (
    <section aria-label="Query history" data-testid="analytics-history" className="space-y-6">
      <div className="card p-4 flex flex-wrap items-end gap-3">
        <div>
          <label className="block text-xs text-muted mb-1" htmlFor="an-range">Time range</label>
          <select id="an-range" className="select" value={range} onChange={(e) => setRange(e.target.value)}>
            {RANGES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </div>
        {scope === 'admin' && (
          <div>
            <label className="block text-xs text-muted mb-1" htmlFor="an-tenant">Tenant</label>
            <select id="an-tenant" className="select" value={tenant} onChange={(e) => { setTenant(e.target.value); setZone(''); }}>
              <option value="">All tenants</option>
              {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </div>
        )}
        <div>
          <label className="block text-xs text-muted mb-1" htmlFor="an-zone">Zone</label>
          <select id="an-zone" className="select" value={zone} onChange={(e) => setZone(e.target.value)}>
            <option value="">All zones</option>
            {(tn?.zones || []).map((z) => <option key={z.domain} value={z.domain}>{z.domain}</option>)}
          </select>
        </div>
        <p className="text-xs text-muted ml-auto">History is kept for {tn?.retention_days ?? '…'} days.</p>
      </div>

      {state.phase === 'error' && <ErrorState title="Could not load analytics" description={state.message} onRetry={load} />}
      {state.phase === 'loading' && <div className="card p-5"><div className="skeleton h-40 w-full" /></div>}

      {state.phase === 'ok' && (
        <>
          <div className="grid sm:grid-cols-3 gap-4">
            <StatCard icon={BarChart3} label={scope === 'admin' && !tenant ? 'Queries to zones' : 'Queries'} value={Number(tn.total_queries).toLocaleString()} hint={`in the selected range`} />
            {scope === 'admin' && <StatCard label="All requests (incl. unknown names)" value={Number(gl?.total || 0).toLocaleString()} hint="global DNS server counter" />}
            <StatCard label="Failed answers" value={Number((tn.series || []).reduce((a, p) => a + p.failed, 0)).toLocaleString()} hint="SERVFAIL, REFUSED, …" />
          </div>

          <div className="card">
            <div className="px-5 py-4 border-b border-line"><h2 className="panel-title">Queries over time</h2></div>
            <div className="p-5 h-64" data-testid="queries-chart">
              {rows.length === 0 ? (
                <EmptyState icon={BarChart3} title="No per-zone query data in this range"
                  description={scope === 'admin'
                    ? 'Per-zone attribution needs the DNS server to run with DNS_ZONE_QUERY_METRICS=true and DNS_METRICS_URL set on the control API. Nothing is estimated.'
                    : 'No queries for your zones have been recorded yet in this range.'} />
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={rows} margin={{ left: 0, right: 8 }}>
                    <defs><linearGradient id="qh" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#F5F020" stopOpacity=".45" /><stop offset="1" stopColor="#F5F020" stopOpacity="0" /></linearGradient></defs>
                    <XAxis dataKey="t" tick={{ fill: tick, fontSize: 11 }} stroke={grid} minTickGap={32} />
                    <YAxis tick={{ fill: tick, fontSize: 11 }} stroke={grid} width={48} />
                    <Tooltip contentStyle={tip} itemStyle={tipItem} />
                    <Area type="monotone" dataKey="queries" stroke="#F5F020" strokeWidth={2} fill="url(#qh)" />
                    <Area type="monotone" dataKey="failed" stroke="#EF4444" strokeWidth={1.5} fill="none" />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {scope === 'admin' && !tenant && globalRows.length > 0 && (
            <div className="card">
              <div className="px-5 py-4 border-b border-line"><h2 className="panel-title">All requests (global counter)</h2></div>
              <div className="p-5 h-52"><ResponsiveContainer width="100%" height="100%"><LineChart data={globalRows}>
                <XAxis dataKey="t" tick={{ fill: tick, fontSize: 11 }} stroke={grid} minTickGap={32} /><YAxis tick={{ fill: tick, fontSize: 11 }} stroke={grid} width={48} /><Tooltip contentStyle={tip} itemStyle={tipItem} />
                <Line type="monotone" dataKey="requests" stroke="#5B7CFA" strokeWidth={2} dot={false} /></LineChart></ResponsiveContainer></div>
            </div>
          )}

          <div className="grid lg:grid-cols-2 gap-6">
            <div className="card overflow-hidden">
              <div className="px-5 py-4 border-b border-line"><h2 className="panel-title">Top zones</h2></div>
              <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Scrollable table"><table className="table" data-testid="top-zones"><thead><tr><th>Zone</th><th className="text-right">Queries</th><th className="text-right">Failed</th></tr></thead>
                <tbody>{(tn.zones || []).map((z) => <tr key={z.domain}><td className="font-mono text-xs">{z.domain}</td><td className="text-right tabular-nums">{z.queries.toLocaleString()}</td><td className="text-right tabular-nums">{z.failed.toLocaleString()}</td></tr>)}
                  {!hasZoneData && <tr><td colSpan="3"><EmptyState title="No data" /></td></tr>}</tbody></table></div>
            </div>
            <div className="card">
              <div className="px-5 py-4 border-b border-line"><h2 className="panel-title">Zones & records over time</h2></div>
              <div className="p-5 h-56">
                {usage.length < 2 ? <EmptyState title="Collecting usage snapshots…" description="One snapshot is stored per hour." /> : (
                  <ResponsiveContainer width="100%" height="100%"><LineChart data={usage}>
                    <XAxis dataKey="t" tick={{ fill: tick, fontSize: 11 }} stroke={grid} minTickGap={32} /><YAxis tick={{ fill: tick, fontSize: 11 }} stroke={grid} width={40} /><Tooltip contentStyle={tip} itemStyle={tipItem} />
                    <Line type="monotone" dataKey="zones" stroke="#F5F020" strokeWidth={2} dot={false} /><Line type="monotone" dataKey="records" stroke="#9B6BFF" strokeWidth={2} dot={false} /></LineChart></ResponsiveContainer>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </section>
  );
}
