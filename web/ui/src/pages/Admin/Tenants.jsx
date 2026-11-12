import React from 'react';
import { Building2, Plus, Pencil, Trash2, Users as UsersIcon } from 'lucide-react';
import api from '../../api/client';
import Notifications from '../../components/Notifications';
import Modal from '../../components/Modal';
import { PageHeader, EmptyState, ErrorState, SkeletonRows, useConfirm } from '../../components/ui';
import { QuotaBar } from '../../components/Quota';
import { apiErrorMessage } from '../../api/errors';

const toQuota = (v) => (v === '' || v == null ? null : Number(v));

export default function Tenants() {
  const notify = React.useContext(Notifications);
  const askConfirm = useConfirm();
  const [rows, setRows] = React.useState(null);
  const [error, setError] = React.useState('');
  const [edit, setEdit] = React.useState(null);      // { id?, name, max_zones, max_records }
  const [members, setMembers] = React.useState(null); // { tenant, list }
  const [newMember, setNewMember] = React.useState({ username: '', role: 'viewer' });

  const load = React.useCallback(async () => {
    const t = localStorage.getItem('token'); if (t) api.setToken(t);
    try { setRows((await api.get('/api/v1/tenants')).data || []); setError(''); } catch (e) { setError(apiErrorMessage(e, 'Failed to load tenants')); }
  }, []);
  React.useEffect(() => { load(); }, [load]);

  const save = async (e) => {
    e.preventDefault();
    const body = { name: edit.name.trim(), max_zones: toQuota(edit.max_zones), max_records: toQuota(edit.max_records) };
    if (!body.name) { notify?.error('A name is required'); return; }
    if ((body.max_zones != null && !(body.max_zones >= 0)) || (body.max_records != null && !(body.max_records >= 0))) { notify?.error('Quotas must be zero or more (leave empty for unlimited)'); return; }
    try {
      if (edit.id) await api.put(`/api/v1/tenants/${edit.id}`, body); else await api.post('/api/v1/tenants', body);
      notify?.success(edit.id ? 'Tenant updated' : 'Tenant created');
      setEdit(null); load();
    } catch (err) { notify?.error(apiErrorMessage(err, 'Save failed')); }
  };

  const remove = async (t) => {
    if (!(await askConfirm({ title: `Delete tenant ${t.name}?`, message: t.zones > 0 ? 'This tenant still owns zones: move or delete them first.' : 'Memberships and stored usage history of this tenant are removed.', confirmLabel: 'Delete tenant' }))) return;
    try { await api.delete(`/api/v1/tenants/${t.id}`); notify?.success('Tenant deleted'); load(); } catch (err) { notify?.error(apiErrorMessage(err, 'Delete failed')); }
  };

  const openMembers = async (t) => {
    try { const r = await api.get(`/api/v1/tenants/${t.id}/members`); setMembers({ tenant: t, list: r.data || [] }); } catch (err) { notify?.error(apiErrorMessage(err, 'Could not load members')); }
  };
  const refreshMembers = async () => { const r = await api.get(`/api/v1/tenants/${members.tenant.id}/members`); setMembers({ ...members, list: r.data || [] }); load(); };
  const addMember = async (e) => {
    e.preventDefault();
    if (!newMember.username.trim()) { notify?.error('Enter a username'); return; }
    try { await api.put(`/api/v1/tenants/${members.tenant.id}/members`, { username: newMember.username.trim(), role: newMember.role }); setNewMember({ username: '', role: 'viewer' }); await refreshMembers(); notify?.success('Member saved'); }
    catch (err) { notify?.error(apiErrorMessage(err, 'Could not save member')); }
  };
  const removeMember = async (m) => {
    if (!(await askConfirm({ title: `Remove ${m.username}?`, message: 'They immediately lose access to this tenant\'s zones.', confirmLabel: 'Remove' }))) return;
    try { await api.delete(`/api/v1/tenants/${members.tenant.id}/members/${m.user_id}`); await refreshMembers(); } catch (err) { notify?.error(apiErrorMessage(err, 'Could not remove member')); }
  };
  const changeRole = async (m, role) => {
    try { await api.put(`/api/v1/tenants/${members.tenant.id}/members`, { user_id: m.user_id, role }); await refreshMembers(); } catch (err) { notify?.error(apiErrorMessage(err, 'Could not change role')); }
  };

  return (
    <div className="page" data-testid="admin-tenants">
      <PageHeader icon={Building2} eyebrow="Administration" title="Tenants & quotas"
        description="A tenant owns zones and has members. Quotas cap zones and DNS records; empty means unlimited. Platform administrators are never limited."
        actions={<button className="btn-primary" onClick={() => setEdit({ name: '', max_zones: '', max_records: '' })}><Plus className="w-4 h-4" />New tenant</button>} />
      {error && <ErrorState title="Could not load tenants" description={error} onRetry={load} />}
      {!error && (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Scrollable table">
            <table className="table" data-testid="tenants-table">
              <thead><tr><th>Tenant</th><th>Zones</th><th>Records</th><th>Members</th><th className="text-right">Actions</th></tr></thead>
              <tbody>
                {rows === null && <SkeletonRows rows={4} cols={5} />}
                {rows?.map((t) => (
                  <tr key={t.id}>
                    <td className="font-medium text-ink">{t.name}</td>
                    <td className="min-w-[180px]"><QuotaBar label="Zones" used={t.zones} limit={t.max_zones} /></td>
                    <td className="min-w-[180px]"><QuotaBar label="Records" used={t.records} limit={t.max_records} /></td>
                    <td className="tabular-nums">{t.members}</td>
                    <td className="text-right">
                      <div className="flex justify-end gap-1">
                        <button className="btn-icon" aria-label={`Members of ${t.name}`} onClick={() => openMembers(t)}><UsersIcon className="w-4 h-4" /></button>
                        <button className="btn-icon" aria-label={`Edit ${t.name}`} onClick={() => setEdit({ id: t.id, name: t.name, max_zones: t.max_zones ?? '', max_records: t.max_records ?? '' })}><Pencil className="w-4 h-4" /></button>
                        <button className="btn-icon text-danger-500" aria-label={`Delete ${t.name}`} onClick={() => remove(t)}><Trash2 className="w-4 h-4" /></button>
                      </div>
                    </td>
                  </tr>
                ))}
                {rows?.length === 0 && <tr><td colSpan="5"><EmptyState icon={Building2} title="No tenants yet" description="Customers get a personal tenant automatically when they create their first zone." /></td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <Modal title={edit?.id ? 'Edit tenant' : 'New tenant'} open={!!edit} onClose={() => setEdit(null)}>
        {edit && (
          <form onSubmit={save} className="space-y-4">
            <div><label className="block text-sm font-medium text-ink/80 mb-1" htmlFor="t-name">Name *</label>
              <input id="t-name" className="input" value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} maxLength={64} /></div>
            <div className="grid sm:grid-cols-2 gap-4">
              <div><label className="block text-sm font-medium text-ink/80 mb-1" htmlFor="t-zones">Max zones</label>
                <input id="t-zones" className="input" type="number" min="0" placeholder="unlimited" value={edit.max_zones} onChange={(e) => setEdit({ ...edit, max_zones: e.target.value })} /></div>
              <div><label className="block text-sm font-medium text-ink/80 mb-1" htmlFor="t-records">Max records</label>
                <input id="t-records" className="input" type="number" min="0" placeholder="unlimited" value={edit.max_records} onChange={(e) => setEdit({ ...edit, max_records: e.target.value })} /></div>
            </div>
            <div className="flex justify-end gap-2"><button type="button" className="btn-secondary" onClick={() => setEdit(null)}>Cancel</button><button className="btn-primary" type="submit">Save</button></div>
          </form>
        )}
      </Modal>

      <Modal title={members ? `Members · ${members.tenant.name}` : 'Members'} open={!!members} onClose={() => setMembers(null)}>
        {members && (
          <div className="space-y-5">
            <table className="table" data-testid="members-table"><thead><tr><th>User</th><th>Role</th><th className="text-right">Remove</th></tr></thead>
              <tbody>{members.list.map((m) => (
                <tr key={m.user_id}><td>{m.username}</td>
                  <td><select className="select input-sm" aria-label={`Role of ${m.username}`} value={m.role} onChange={(e) => changeRole(m, e.target.value)}><option value="owner">owner</option><option value="editor">editor</option><option value="viewer">viewer</option></select></td>
                  <td className="text-right"><button className="btn-icon text-danger-500" aria-label={`Remove ${m.username}`} onClick={() => removeMember(m)}><Trash2 className="w-4 h-4" /></button></td></tr>
              ))}</tbody></table>
            <form onSubmit={addMember} className="flex flex-wrap items-end gap-2">
              <div className="flex-1 min-w-[160px]"><label className="block text-xs text-muted mb-1" htmlFor="m-user">Username</label><input id="m-user" className="input" value={newMember.username} onChange={(e) => setNewMember({ ...newMember, username: e.target.value })} /></div>
              <div><label className="block text-xs text-muted mb-1" htmlFor="m-role">Role</label><select id="m-role" className="select" value={newMember.role} onChange={(e) => setNewMember({ ...newMember, role: e.target.value })}><option value="viewer">viewer</option><option value="editor">editor</option><option value="owner">owner</option></select></div>
              <button className="btn-primary" type="submit">Add member</button>
            </form>
            <p className="text-xs text-muted">Owners manage members and zones, editors change records, viewers read.</p>
          </div>
        )}
      </Modal>
    </div>
  );
}
