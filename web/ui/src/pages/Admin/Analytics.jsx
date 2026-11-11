import React, { useEffect, useRef, useState, useCallback } from 'react';
import { BarChart3, RefreshCw } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import api from '../../api/client';
import { useUIStore } from '../../store';
import { PageHeader, EmptyState, ErrorState, StatCard } from '../../components/ui';

const POLL_MS = 10000;

// DNS query analytics from the DNS server's own Prometheus counters (via the control API).
// The rate chart is computed in the browser from consecutive samples taken while this page is open.
export default function Analytics() {
  const [state, setState] = useState({ phase: 'loading' });
  const [series, setSeries] = useState([]);
  const last = useRef(null);
  const theme = useUIStore((s) => s.theme);

  const sample = useCallback(async () => {
    try {
      const { data } = await api.get('/api/v1/metrics/queries');
      const now = Date.now();
      if (last.current && now > last.current.t) {
        const qps = Math.max(0, (data.requests_total - last.current.v) / ((now - last.current.t) / 1000));
        setSeries((s) => [...s.slice(-59), { t: new Date(now).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }), qps: Number(qps.toFixed(2)) }]);
      }
      last.current = { t: now, v: data.requests_total };
      setState({ phase: 'ok', ...data });
    } catch (e) {
      setState({ phase: e.response?.status === 503 ? 'unconfigured' : 'error', message: e.response?.data?.details || e.response?.data?.error || e.message });
    }
  }, []);

  useEffect(() => {
    const t = localStorage.getItem('token'); if (t) api.setToken(t);
    sample();
    const id = setInterval(sample, POLL_MS);
    return () => clearInterval(id);
  }, [sample]);

  const grid = theme === 'dark' ? '#232836' : '#E2E2DA';
  const tick = theme === 'dark' ? '#9AA3B5' : '#5F6677';
  const counters = state.phase === 'ok' ? Object.entries(state.counters || {}).sort((a, b) => b[1] - a[1]) : [];

  return (
    <div className="page">
      <PageHeader icon={BarChart3} eyebrow="Insights" title="Analytics" description="Query counters reported by the DNS server."
        actions={<button className="btn-secondary" onClick={sample}><RefreshCw className="w-4 h-4" />Refresh</button>} />

      {state.phase === 'loading' && <div className="grid sm:grid-cols-3 gap-4">{[0, 1, 2].map((i) => <div key={i} className="card p-5"><div className="skeleton h-8 w-24" /></div>)}</div>}
      {state.phase === 'unconfigured' && <div className="card"><EmptyState icon={BarChart3} title="Query statistics are not configured" description="Point DNS_METRICS_URL on the control API at the DNS server's Prometheus endpoint (for example http://dns:9000/metrics)." /></div>}
      {state.phase === 'error' && <ErrorState title="Could not read the DNS server's metrics" description={state.message} onRetry={sample} />}

      {state.phase === 'ok' && (
        <>
          <div className="grid sm:grid-cols-3 gap-4">
            <StatCard icon={BarChart3} label="Requests answered" value={Number(state.requests_total).toLocaleString()} hint="since the DNS server started" />
            <StatCard label="Current rate" value={series.length ? `${series[series.length - 1].qps} /s` : '…'} hint={`sampled every ${POLL_MS / 1000}s while this page is open`} />
            <StatCard label="Source" value="Prometheus" hint={state.source} />
          </div>

          <div className="card">
            <div className="px-5 py-4 border-b border-line"><h2 className="panel-title">Queries per second</h2></div>
            <div className="p-5 h-64">
              {series.length < 2 ? <EmptyState title="Collecting samples…" description="The rate appears after two samples." /> : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={series} margin={{ left: 0, right: 8 }}>
                    <defs><linearGradient id="qps" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#F5F020" stopOpacity=".45" /><stop offset="1" stopColor="#F5F020" stopOpacity="0" /></linearGradient></defs>
                    <XAxis dataKey="t" tick={{ fill: tick, fontSize: 11 }} stroke={grid} minTickGap={32} />
                    <YAxis tick={{ fill: tick, fontSize: 11 }} stroke={grid} width={44} />
                    <Tooltip contentStyle={{ background: theme === 'dark' ? '#181C25' : '#fff', border: `1px solid ${grid}`, borderRadius: 8, fontSize: 12 }} />
                    <Area type="monotone" dataKey="qps" stroke="#F5F020" strokeWidth={2} fill="url(#qps)" />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="card overflow-hidden">
            <div className="px-5 py-4 border-b border-line"><h2 className="panel-title">Counters</h2></div>
            <div className="overflow-x-auto"><table className="table"><thead><tr><th>Metric</th><th className="text-right">Value</th></tr></thead>
              <tbody>{counters.map(([k, v]) => <tr key={k}><td className="font-mono text-xs">{k}</td><td className="text-right tabular-nums">{Number(v).toLocaleString()}</td></tr>)}
                {counters.length === 0 && <tr><td colSpan="2"><EmptyState title="No counters reported yet" /></td></tr>}</tbody></table></div>
          </div>
        </>
      )}
    </div>
  );
}
