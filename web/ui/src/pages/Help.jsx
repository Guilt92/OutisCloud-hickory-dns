import React from 'react';
import { LifeBuoy, Globe, FileText, ShieldCheck, MapPin } from 'lucide-react';
import { PageHeader } from '../components/ui';

const topics = [
  { icon: Globe, title: 'Point your domain to OutisCloud', body: 'Add the zone, then set your domain\'s nameservers at your registrar to the nameservers shown under Zones → your zone. Changes can take up to 48 hours to propagate.' },
  { icon: FileText, title: 'Record types', body: 'A/AAAA map names to IPv4/IPv6 addresses, CNAME aliases a name to another name (not allowed at the zone apex), MX routes email, TXT holds text such as SPF, and NS delegates a subdomain.' },
  { icon: ShieldCheck, title: 'Domain verification', body: 'If a zone shows "Pending verification", create the TXT record named in the zone dialog at your current DNS provider, then press Verify. The zone is served once verification succeeds.' },
  { icon: MapPin, title: 'Geo-routing and DNSSEC', body: 'Geo-routing and DNSSEC are configured by your administrator or in the zone\'s Manage dialog where enabled. DNSSEC needs a DS record at your registrar; GeoDNS and DNSSEC cannot be combined on one zone.' },
];

export default function Help() {
  return (
    <div className="page max-w-3xl">
      <PageHeader icon={LifeBuoy} eyebrow="Support" title="Help & documentation" description="Short answers to the questions customers ask most." />
      <div className="grid gap-4">
        {topics.map((t) => (
          <section key={t.title} className="card p-5 flex gap-4">
            <div className="icon-box"><t.icon className="w-5 h-5" /></div>
            <div><h2 className="font-display font-semibold text-ink">{t.title}</h2><p className="text-sm text-muted mt-1">{t.body}</p></div>
          </section>
        ))}
      </div>
      <p className="text-sm text-muted">Need more help? Contact your service administrator.</p>
    </div>
  );
}
