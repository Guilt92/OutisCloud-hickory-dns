import React from 'react';
import { ArrowRight } from 'lucide-react';
import api from '../api/client';
import Notifications from './Notifications';
import Modal from './Modal';
import { useConfirm } from './ui';
import { apiErrorMessage } from '../api/errors';

// Administrator-only workflow: pick a destination tenant, review source -> destination, confirm.
// The API does the move in ONE transaction (quota-checked, audited); records, GeoDNS rules and DNSSEC stay with the zone.
export default function TransferZone({ zone, onClose, onDone }) {
  const notify = React.useContext(Notifications);
  const askConfirm = useConfirm();
  const [tenants, setTenants] = React.useState(null);
  const [dest, setDest] = React.useState('');
  const [keepShares, setKeepShares] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    api.get('/api/v1/tenants').then((r) => setTenants(r.data || [])).catch((e) => notify?.error(apiErrorMessage(e, 'Could not load tenants')));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const options = (tenants || []).filter((t) => t.id !== zone.tenant_id);
  const target = options.find((t) => t.id === dest);
  const sourceName = zone.tenant_name || 'Platform (no tenant)';

  const submit = async (e) => {
    e.preventDefault();
    if (!dest) { notify?.error('Choose a destination tenant'); return; }
    const ok = await askConfirm({
      title: `Transfer ${zone.domain}?`,
      message: `${sourceName} → ${target.name}. The zone, its records and GeoDNS rules move together. ${keepShares ? 'Existing shares are kept.' : 'Explicit per-user shares are removed.'} Members of ${sourceName} lose access unless they belong to ${target.name}.`,
      confirmLabel: 'Transfer zone', danger: false,
    });
    if (!ok) return;
    setBusy(true);
    try {
      const r = await api.put(`/api/v1/zones/${zone.id}/tenant`, { tenant_id: dest, keep_shares: keepShares });
      notify?.success(`${zone.domain} moved to ${r.data.to.name} (${r.data.records} records${r.data.shares_removed ? `, ${r.data.shares_removed} share(s) removed` : ''})`);
      onDone && onDone();
      onClose();
    } catch (err) {
      notify?.error(apiErrorMessage(err, 'Transfer failed') + ' The zone was not changed.');
    } finally { setBusy(false); }
  };

  return (
    <Modal title={`Transfer ${zone.domain}`} open onClose={onClose}>
      <form onSubmit={submit} className="space-y-4" data-testid="transfer-form">
        <div className="flex items-center gap-3 text-sm">
          <div className="card px-3 py-2"><span className="block text-xs text-muted">Current tenant</span><span data-testid="transfer-source" className="font-medium text-ink">{sourceName}</span></div>
          <ArrowRight className="w-4 h-4 text-muted" aria-hidden="true" />
          <div className="card px-3 py-2"><span className="block text-xs text-muted">Destination</span><span className="font-medium text-ink">{target ? target.name : '—'}</span></div>
        </div>
        <div>
          <label className="form-label" htmlFor="transfer-dest">Destination tenant</label>
          <select id="transfer-dest" className="select w-full" value={dest} onChange={(e) => setDest(e.target.value)} disabled={!tenants}>
            <option value="">{tenants ? 'Select a tenant…' : 'Loading…'}</option>
            {options.map((t) => (
              <option key={t.id} value={t.id}>{t.name} — {t.zones}{t.max_zones != null ? ` / ${t.max_zones}` : ''} zones, {t.records}{t.max_records != null ? ` / ${t.max_records}` : ''} records</option>
            ))}
          </select>
          {tenants && options.length === 0 && <p className="text-xs text-muted mt-1">There is no other tenant to move this zone to.</p>}
        </div>
        <label className="flex items-center gap-2 text-sm text-ink/80 cursor-pointer">
          <input type="checkbox" checked={keepShares} onChange={(e) => setKeepShares(e.target.checked)} /> Keep existing per-user shares of the zone
        </label>
        <p className="text-xs text-muted">The destination tenant&apos;s zone and record quotas apply; the transfer is refused as a whole if they would be exceeded.</p>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn-primary" disabled={busy || !dest}>{busy ? 'Transferring…' : 'Review & transfer'}</button>
        </div>
      </form>
    </Modal>
  );
}
