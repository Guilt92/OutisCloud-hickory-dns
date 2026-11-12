import React from 'react';

// Usage vs. limit. `limit == null` means unlimited (no bar, never invented).
export function QuotaBar({ label, used, limit }) {
  const unlimited = limit == null;
  const pct = unlimited ? 0 : Math.min(100, limit === 0 ? 100 : Math.round((used / limit) * 100));
  const tone = pct >= 100 ? 'bg-danger-500' : pct >= 80 ? 'bg-warning-500' : 'bg-accent';
  return (
    <div data-testid={`quota-${label.toLowerCase()}`}>
      <div className="flex items-baseline justify-between text-sm">
        <span className="text-ink">{label}</span>
        <span className="tabular-nums text-muted">{used.toLocaleString()} / {unlimited ? 'unlimited' : limit.toLocaleString()}</span>
      </div>
      {!unlimited && (
        <div className="mt-1.5 h-2 rounded-full bg-ink/10 overflow-hidden" role="progressbar" aria-label={`${label} used`} aria-valuemin={0} aria-valuemax={limit} aria-valuenow={used}>
          <div className={`h-full ${tone}`} style={{ width: `${pct}%` }} />
        </div>
      )}
    </div>
  );
}
