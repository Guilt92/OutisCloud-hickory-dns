import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Globe, FileText, Search, ShieldCheck, LifeBuoy, ArrowRight, Plus, CheckCircle2, Clock, Lock } from 'lucide-react';
import api from '../api/client';
import { useAuthStore } from '../store';
import { StatCard, EmptyState, FlowArt, StatusBadge } from '../components/ui';
import { QuotaBar } from '../components/Quota';

// Customer overview: only the customer's own zones (the API enforces tenancy), nothing about infrastructure.
export default function UserOverview() {
  const { user } = useAuthStore();
  const [d, setD] = useState({ loading: true });
  const canWrite = user?.role !== 'viewer';

  useEffect(() => {
    const t = localStorage.getItem('token'); if (t) api.setToken(t);
    (async () => {
      // ONE aggregated, tenant-scoped request: zones with record counts and quota usage
      const r = await api.get('/api/v1/overview').catch(() => null);
      const ov = r?.data;
      setD({ loading: false, error: !ov, zones: ov?.zones || [], zoneTotal: ov?.zones_total ?? 0, records: ov?.records_total ?? 0, tenants: ov?.tenants || [] });
    })();
  }, []);

  const pending = (d.zones || []).filter((z) => z.status === 'pending');
  const recent = (d.zones || []).slice(0, 6);

  return (
    <div className="page" data-testid="user-overview">
      <div className="relative overflow-hidden rounded-[24px] border border-line bg-surface p-6 sm:p-8">
        <FlowArt className="absolute inset-0 w-full h-full text-ink/[0.055]" />
        <div className="relative max-w-xl">
          <p className="eyebrow mb-2">Welcome back</p>
          <h1 className="font-display text-[30px] sm:text-[36px] leading-[1.08] font-semibold tracking-[-0.035em] text-ink">Hello, {user?.username}</h1>
          <p className="text-muted mt-2">Manage your domains and DNS records.</p>
          <div className="mt-5 flex flex-wrap gap-2">
            <Link to="/user/zones" className="btn-primary">{canWrite ? <><Plus className="w-4 h-4" />Add or manage zones</> : <>View zones <ArrowRight className="w-4 h-4" /></>}</Link>
            <Link to="/user/dns-lookup" className="btn-secondary"><Search className="w-4 h-4" />Check a domain</Link>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <StatCard icon={Globe} label="Your zones" value={d.zoneTotal ?? '—'} to="/user/zones" loading={d.loading} />
        <StatCard icon={FileText} label="DNS records" value={d.records ?? '—'} hint="across your zones" loading={d.loading} />
        <StatCard icon={ShieldCheck} label="Needs verification" value={pending.length} tone={pending.length ? 'warn' : 'ok'} hint={pending.length ? 'publish the TXT challenge' : 'all zones verified'} loading={d.loading} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="card xl:col-span-2">
          <div className="px-5 py-4 border-b border-line flex items-center justify-between"><h2 className="panel-title">Your zones</h2><Link to="/user/zones" className="text-xs text-muted hover:text-ink hover:underline">View all</Link></div>
          {d.error ? <EmptyState title="Could not load your zones" description="Please try again in a moment." /> :
            !d.loading && recent.length === 0 ? <EmptyState icon={Globe} title="No zones yet" description="Add your first domain to start serving DNS." action={canWrite && <Link to="/user/zones" className="btn-primary btn-sm">Add a zone</Link>} /> : (
              <ul className="divide-y divide-line">
                {d.loading && [0, 1, 2].map((i) => <li key={i} className="px-5 py-4"><div className="skeleton h-4 w-48" /></li>)}
                {recent.map((z) => (
                  <li key={z.id}>
                    <Link to={`/user/zones/${z.id}/records`} className="flex items-center gap-3 px-5 py-3.5 hover:bg-ink/[0.03]">
                      <span className={z.status === 'pending' ? 'dot-warn' : 'dot-ok'} />
                      <span className="font-medium text-ink">{z.domain}</span>
                      {z.access && z.access !== 'owner' && <span className="badge-info">shared · {z.access}</span>}
                      <span className="flex-1" />
                      <StatusBadge status={z.status === 'pending' ? 'pending' : 'active'}>{z.status === 'pending' ? 'Pending verification' : 'Active'}</StatusBadge>
                      <ArrowRight className="w-4 h-4 text-muted" />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
        </div>

        <div className="space-y-6">
          {(d.tenants || []).map((t) => (
            <div key={t.id} className="card p-5 space-y-3" data-testid="quota-card">
              <h2 className="panel-title">Plan & usage <span className="text-xs text-muted font-normal">· {t.name}</span></h2>
              <div data-testid="quota-zones"><QuotaBar label="Zones" used={t.zones} limit={t.max_zones} /></div>
              <div data-testid="quota-records"><QuotaBar label="Records" used={t.records} limit={t.max_records} /></div>
            </div>
          ))}
          <div className="card p-5">
            <h2 className="panel-title mb-3">Service status</h2>
            <div className="flex items-center gap-2 text-sm text-ink"><CheckCircle2 className="w-4 h-4 text-success-500" />{pending.length ? `${pending.length} zone(s) not served yet` : 'Your zones are being served'}</div>
            <p className="text-xs text-muted mt-2 flex items-center gap-1.5"><Clock className="w-3.5 h-3.5" />Record changes are published automatically.</p>
          </div>
          <div className="card p-5">
            <h2 className="panel-title mb-3">Help</h2>
            <div className="space-y-2 text-sm">
              <Link to="/user/help" className="flex items-center gap-2 text-ink hover:underline"><LifeBuoy className="w-4 h-4 text-muted" />Guides & DNS basics</Link>
              <Link to="/user/settings" className="flex items-center gap-2 text-ink hover:underline"><Lock className="w-4 h-4 text-muted" />Password & two-factor authentication</Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
