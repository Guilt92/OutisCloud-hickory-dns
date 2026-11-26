import { randomUUID } from 'node:crypto';

const recordKey = ({ name, record_type, value }) => `${name}\u0000${record_type}\u0000${value}`;

export async function planDesiredState(client, desired) {
  if (!desired || !Array.isArray(desired.zones)) throw new TypeError('desired state must contain a zones array');
  const currentZones = [];
  for await (const zone of client.paginate('/api/v1/zones')) currentZones.push(zone);
  const byDomain = new Map(currentZones.map((zone) => [zone.domain.toLowerCase(), zone]));
  const actions = [];
  const seenDomains = new Set();

  for (const zone of desired.zones) {
    if (!zone?.domain || typeof zone.domain !== 'string') throw new TypeError('every desired zone must have a domain');
    const domain = zone.domain.toLowerCase().replace(/\.$/, '');
    if (seenDomains.has(domain)) throw new TypeError(`duplicate desired zone: ${domain}`);
    seenDomains.add(domain);
    const existing = byDomain.get(domain);
    if (!existing) {
      actions.push({
        action: 'create-zone',
        domain,
        zone_type: zone.zone_type || 'primary',
        tenant_id: zone.tenant_id,
        geodns_enabled: zone.geodns_enabled,
        ecs_enabled: zone.ecs_enabled,
      });
    } else {
      const changes = {};
      for (const field of ['geodns_enabled', 'ecs_enabled']) {
        if (zone[field] !== undefined && Boolean(zone[field]) !== Boolean(existing[field])) changes[field] = Boolean(zone[field]);
      }
      if (Object.keys(changes).length) actions.push({ action: 'update-zone', domain, zoneId: existing.id, changes });
    }
    const zoneRecords = existing
      ? await client.request('GET', '/api/v1/zones/{id}/records', { params: { id: existing.id } })
      : { data: [] };
    const currentRecords = Array.isArray(zoneRecords.data) ? zoneRecords.data : [];
    const indexedRecords = new Map(currentRecords.map((record) => [recordKey(record), record]));
    const desiredRecords = new Map();
    for (const record of zone.records || []) {
      if (!record?.name || !record.record_type || record.value === undefined || !Number.isInteger(record.ttl) || record.ttl < 1) {
        throw new TypeError(`invalid record in desired zone ${domain}`);
      }
      const key = recordKey(record);
      if (desiredRecords.has(key)) throw new TypeError(`duplicate record in desired zone ${domain}: ${record.name}`);
      desiredRecords.set(key, record);
      const actual = indexedRecords.get(key);
      if (!actual) actions.push({ action: 'create-record', domain, zoneId: existing?.id, record });
      else if (actual.ttl !== record.ttl || (actual.priority || 0) !== (record.priority || 0)) {
        actions.push({ action: 'update-record', domain, zoneId: existing.id, recordId: actual.id, record });
      }
    }
    if (desired.prune === true && existing) {
      for (const actual of currentRecords) {
        if (!desiredRecords.has(recordKey(actual)) && !['SOA', 'NS'].includes(actual.record_type)) {
          actions.push({ action: 'delete-record', domain, zoneId: existing.id, recordId: actual.id });
        }
      }
    }
  }
  return actions;
}

export async function applyPlan(client, actions, { dryRun = true, allowDestructive = false } = {}) {
  if (!Array.isArray(actions)) throw new TypeError('plan must be an array');
  if (dryRun) return { dryRun: true, actions };
  if (!allowDestructive && actions.some(({ action }) => action === 'delete-record')) {
    throw new Error('destructive plan requires allowDestructive=true');
  }
  const createdZones = new Map();
  const results = [];
  for (const item of actions) {
    if (item.action === 'create-zone') {
      const result = await client.request('POST', '/api/v1/zones', {
        body: {
          domain: item.domain,
          zone_type: item.zone_type,
          tenant_id: item.tenant_id,
          geodns_enabled: item.geodns_enabled,
          ecs_enabled: item.ecs_enabled,
        },
        headers: { 'Idempotency-Key': randomUUID() },
      });
      createdZones.set(item.domain, result.data.id);
      results.push({ action: item.action, domain: item.domain, result: result.data });
    } else {
      const zoneId = item.zoneId || createdZones.get(item.domain);
      if (!zoneId) throw new Error(`plan references unavailable zone ${item.domain}`);
      let result;
      if (item.action === 'update-zone') {
        result = await client.request('PUT', `/api/v1/zones/${encodeURIComponent(zoneId)}`, {
          body: item.changes,
          headers: { 'Idempotency-Key': randomUUID() },
        });
      } else if (item.action === 'create-record') {
        result = await client.request('POST', `/api/v1/zones/${encodeURIComponent(zoneId)}/records`, {
          body: item.record,
          headers: { 'Idempotency-Key': randomUUID() },
        });
      } else if (item.action === 'update-record') {
        result = await client.request('PUT', `/api/v1/zones/${encodeURIComponent(zoneId)}/records/${encodeURIComponent(item.recordId)}`, {
          body: { ttl: item.record.ttl, priority: item.record.priority || 0 },
          headers: { 'Idempotency-Key': randomUUID() },
        });
      } else if (item.action === 'delete-record') {
        result = await client.request('DELETE', `/api/v1/zones/${encodeURIComponent(zoneId)}/records/${encodeURIComponent(item.recordId)}`, {
          headers: { 'Idempotency-Key': randomUUID() },
        });
      } else throw new Error(`unknown plan action: ${item.action}`);
      results.push({ action: item.action, domain: item.domain, result: result.data });
    }
  }
  return { dryRun: false, results };
}
