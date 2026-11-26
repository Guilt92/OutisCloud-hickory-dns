import { operations } from './generated.js';

const RETRYABLE = new Set([429, 500, 502, 503, 504]);
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export class ApiError extends Error {
  constructor(status, payload, headers) {
    super(payload?.details || payload?.error || `OutisCloud API returned HTTP ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.code = payload?.code;
    this.payload = payload;
    this.headers = headers;
  }
}

function retryDelay(response, attempt, maxDelayMs) {
  const value = response.headers.get('Retry-After');
  if (value) {
    const seconds = Number(value);
    const delay = Number.isFinite(seconds) ? seconds * 1000 : Date.parse(value) - Date.now();
    if (Number.isFinite(delay)) return Math.min(maxDelayMs, Math.max(0, delay));
  }
  return Math.min(maxDelayMs, 200 * 2 ** attempt);
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class OutisCloudClient {
  constructor({ baseUrl, token, fetchImpl = globalThis.fetch, retries = 2, maxRetryDelayMs = 5000 } = {}) {
    if (!baseUrl) throw new TypeError('baseUrl is required');
    if (typeof fetchImpl !== 'function') throw new TypeError('fetch implementation is required');
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.token = token;
    this.fetch = fetchImpl;
    this.retries = Math.max(0, Math.min(5, retries));
    this.maxRetryDelayMs = Math.max(0, maxRetryDelayMs);
  }

  async request(method, route, { params = {}, query = {}, body, headers = {}, signal } = {}) {
    const upperMethod = method.toUpperCase();
    const replacements = Object.fromEntries(Object.entries(params).map(([key, value]) => [key, encodeURIComponent(String(value))]));
    const resolvedPath = route.replace(/\{([^}]+)\}/g, (_, key) => {
      if (!(key in replacements)) throw new TypeError(`missing path parameter: ${key}`);
      return replacements[key];
    });
    if (/\{[^}]+\}/.test(resolvedPath)) throw new TypeError('unresolved path parameter');
    const url = new URL(resolvedPath, `${this.baseUrl}/`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null) continue;
      if (Array.isArray(value)) value.forEach((item) => url.searchParams.append(key, String(item)));
      else url.searchParams.set(key, String(value));
    }
    const requestHeaders = new Headers(headers);
    if (this.token) requestHeaders.set('Authorization', `Bearer ${this.token}`);
    if (body !== undefined) requestHeaders.set('Content-Type', 'application/json');
    const canRetry = SAFE_METHODS.has(upperMethod) || requestHeaders.has('Idempotency-Key');
    for (let attempt = 0; ; attempt += 1) {
      const response = await this.fetch(url, {
        method: upperMethod,
        headers: requestHeaders,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal,
      });
      if (RETRYABLE.has(response.status) && canRetry && attempt < this.retries) {
        await wait(retryDelay(response, attempt, this.maxRetryDelayMs));
        continue;
      }
      const contentType = response.headers.get('Content-Type') || '';
      const payload = response.status === 204 ? undefined
        : contentType.includes('json') ? await response.json()
          : await response.text();
      if (!response.ok) throw new ApiError(response.status, payload, response.headers);
      return { data: payload, status: response.status, headers: response.headers };
    }
  }

  async call(operationId, options = {}) {
    const operation = operations.find(({ id }) => id === operationId);
    if (!operation) throw new TypeError(`unknown OpenAPI operation: ${operationId}`);
    return this.request(operation.method, operation.path, options);
  }

  async *paginate(route, { method = 'GET', query = {}, params = {}, body, pageSize = 100, signal } = {}) {
    const size = Number(pageSize);
    if (!Number.isFinite(size) || size < 1) throw new TypeError('pageSize must be a positive number');
    pageSize = Math.min(1000, Math.floor(size));
    let offset = Number(query.offset || 0);
    let cursor = query.cursor;
    for (;;) {
      const usingCursor = Boolean(cursor);
      const pageQuery = { ...query, limit: pageSize };
      if (cursor) {
        pageQuery.cursor = cursor;
        delete pageQuery.offset;
      } else {
        pageQuery.offset = offset;
      }
      const result = await this.request(method, route, { params, query: pageQuery, body, signal });
      const rows = Array.isArray(result.data) ? result.data
        : Array.isArray(result.data?.data) ? result.data.data : [];
      for (const row of rows) yield row;
      const nextCursor = result.headers.get('X-Next-Cursor');
      if (nextCursor) {
        cursor = nextCursor;
        continue;
      }
      if (usingCursor) return;
      const total = Number(result.headers.get('X-Total-Count'));
      offset += rows.length;
      if (!rows.length || !Number.isFinite(total) || offset >= total) return;
    }
  }
}
