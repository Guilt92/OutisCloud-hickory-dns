import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { OutisCloudClient, ApiError } from '../src/client.js';
import { operations } from '../src/generated.js';
import { applyPlan, planDesiredState } from '../src/reconcile.js';

async function withServer(handler, run) {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try { await run(`http://127.0.0.1:${server.address().port}`); }
  finally { server.close(); await once(server, 'close'); }
}

test('auth, path encoding, query params and JSON request bodies', async () => {
  await withServer(async (req, res) => {
    assert.equal(req.headers.authorization, 'Bearer secret');
    assert.equal(req.url, '/zones/a%2Fb?limit=2');
    assert.equal(req.headers['content-type'], 'application/json');
    let raw = '';
    for await (const chunk of req) raw += chunk;
    assert.deepEqual(JSON.parse(raw), { enabled: true });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"ok":true}');
  }, async (baseUrl) => {
    const client = new OutisCloudClient({ baseUrl, token: 'secret' });
    const result = await client.request('PUT', '/zones/{id}', {
      params: { id: 'a/b' }, query: { limit: 2 }, body: { enabled: true },
    });
    assert.deepEqual(result.data, { ok: true });
  });
});

test('generated operation registry invokes the OpenAPI route catalog', async () => {
  assert.equal(operations.length, 116);
  assert.ok(operations.some(({ id }) => id === 'get_api_v1_zones'));
  let requested;
  const client = new OutisCloudClient({
    baseUrl: 'http://example.invalid',
    fetchImpl: async (url, init) => {
      requested = [String(url), init.method];
      return new Response('[]', { status: 200, headers: { 'Content-Type': 'application/json' } });
    },
  });
  await client.call('get_api_v1_zones', { query: { limit: 2 } });
  assert.deepEqual(requested, ['http://example.invalid/api/v1/zones?limit=2', 'GET']);
});

test('retries safe requests on 503 and honors Retry-After', async () => {
  let count = 0;
  await withServer((_req, res) => {
    count += 1;
    if (count === 1) { res.writeHead(503, { 'Retry-After': '0' }); res.end('{}'); }
    else { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('[]'); }
  }, async (baseUrl) => {
    const client = new OutisCloudClient({ baseUrl, retries: 1 });
    assert.deepEqual((await client.request('GET', '/zones')).data, []);
    assert.equal(count, 2);
  });
});

test('does not retry non-idempotent writes without an idempotency key', async () => {
  let count = 0;
  await withServer((_req, res) => { count += 1; res.writeHead(503); res.end('{}'); }, async (baseUrl) => {
    const client = new OutisCloudClient({ baseUrl, retries: 2 });
    await assert.rejects(client.request('POST', '/zones', { body: {} }), ApiError);
    assert.equal(count, 1);
  });
});

test('pagination follows opaque cursors and yields rows across pages', async () => {
  let count = 0;
  await withServer((_req, res) => {
    count += 1;
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'X-Total-Count': '3',
      ...(count === 1 ? { 'X-Next-Cursor': 'opaque-next' } : {}),
    });
    res.end(JSON.stringify({ data: count === 1 ? [{ id: 1 }, { id: 2 }] : [{ id: 3 }] }));
  }, async (baseUrl) => {
    const client = new OutisCloudClient({ baseUrl });
    const rows = [];
    for await (const row of client.paginate('/zones', { pageSize: 2 })) rows.push(row);
    assert.deepEqual(rows, [{ id: 1 }, { id: 2 }, { id: 3 }]);
    assert.equal(count, 2);
  });
});

test('declarative plan is repeatable, dry-run safe, and explicit about pruning', async () => {
  const current = [{ id: 'z1', domain: 'example.test' }];
  const client = {
    async *paginate() { yield* current; },
    async request(method, route) {
      assert.equal(method, 'GET');
      assert.equal(route, '/api/v1/zones/{id}/records');
      return { data: [
        { id: 'r1', name: 'www', record_type: 'A', value: '192.0.2.1', ttl: 60 },
        { id: 'r2', name: 'old', record_type: 'TXT', value: 'remove-me', ttl: 60 },
        { id: 'r3', name: '@', record_type: 'NS', value: 'ns1.example.test.', ttl: 3600 },
      ] };
    },
  };
  const desired = { zones: [{ domain: 'EXAMPLE.TEST.', records: [
    { name: 'www', record_type: 'A', value: '192.0.2.1', ttl: 300 },
    { name: 'api', record_type: 'A', value: '192.0.2.2', ttl: 300 },
  ] }] };
  const plan = await planDesiredState(client, desired);
  assert.deepEqual(plan.map(({ action }) => action), ['update-record', 'create-record']);
  assert.deepEqual(await applyPlan(client, plan), { dryRun: true, actions: plan });
  const pruning = await planDesiredState(client, { ...desired, prune: true });
  assert.deepEqual(pruning.map(({ action }) => action), ['update-record', 'create-record', 'delete-record']);
  await assert.rejects(applyPlan(client, pruning, { dryRun: false }), /allowDestructive/);
});

test('applying a new desired zone creates it before adding its records', async () => {
  const calls = [];
  const client = {
    async *paginate() {},
    async request(method, route, options) {
      calls.push({ method, route, options });
      if (route === '/api/v1/zones') return { data: { id: 'new-zone' } };
      return { data: { id: 'new-record' } };
    },
  };
  const plan = await planDesiredState(client, { zones: [{
    domain: 'new.example.test',
    records: [{ name: 'www', record_type: 'A', value: '192.0.2.4', ttl: 300 }],
  }] });
  assert.deepEqual(plan.map(({ action }) => action), ['create-zone', 'create-record']);
  const result = await applyPlan(client, plan, { dryRun: false });
  assert.equal(result.results.length, 2);
  assert.equal(calls[0].route, '/api/v1/zones');
  assert.equal(calls[1].route, '/api/v1/zones/new-zone/records');
  assert.ok(calls.every(({ options }) => options.headers['Idempotency-Key']));
});
