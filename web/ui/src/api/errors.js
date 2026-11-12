// Human-readable text for an API error. Quota refusals carry structured data (see tenants.rs).
export function apiErrorMessage(err, fallback = 'Request failed') {
  const d = err?.response?.data;
  if (d?.error === 'quota_exceeded') {
    return `Quota reached: your plan allows ${d.limit} ${d.quota} and ${d.used} are in use. Ask an administrator to raise the limit or remove unused ${d.quota}.`;
  }
  if (err?.response?.status === 429) return d?.details || 'Too many requests, please wait a moment.';
  return d?.details && typeof d.details === 'string' && d.error === 'publish_failed' ? d.details : (d?.error || err?.message || fallback);
}
