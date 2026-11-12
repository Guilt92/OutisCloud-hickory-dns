import React from 'react';
import { BarChart3 } from 'lucide-react';
import { PageHeader } from '../components/ui';
import AnalyticsHistory from '../components/AnalyticsHistory';

// Customer analytics: the API only ever returns data of the caller's own tenant.
export default function UserAnalytics() {
  return (
    <div className="page" data-testid="user-analytics">
      <PageHeader icon={BarChart3} eyebrow="Insights" title="Query analytics" description="How often your zones are queried. Only your own zones are included." />
      <AnalyticsHistory scope="tenant" />
    </div>
  );
}
