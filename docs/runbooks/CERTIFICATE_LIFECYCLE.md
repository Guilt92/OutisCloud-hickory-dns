# TLS certificate lifecycle

The control API serves plain HTTP on port 8080 and is expected to sit behind a TLS
reverse proxy (see `docs/adr/ADR-0004-*`). Certificates are therefore managed on the
proxy or ingress, not inside the application.

## Inventory

Record for every certificate: hostnames, issuer, expiry, renewal owner, and where the
private key lives. Private keys must never be committed, logged, or copied into the
repository. The secret scan intentionally flags tracked key material.

## Check expiry

```bash
scripts/check_certs.sh /etc/letsencrypt/live/dns.example.com/fullchain.pem
scripts/check_certs.sh /etc/ssl/certs/*.pem --json
```

Exit codes: `0` all certificates valid for the warning window (default 30 days),
`1` at least one expires inside it, `2` at least one expires inside the critical
window (default 7 days) or cannot be parsed. Run it from cron and alert on non-zero.

## Renew

- ACME (recommended): let the proxy or certbot renew automatically; reload the proxy
  after renewal (`systemctl reload nginx` or the ingress equivalent).
- Manual: issue the new certificate, install it with the private key readable only by
  the proxy user, reload, then verify from outside:

```bash
openssl s_client -connect dns.example.com:443 -servername dns.example.com </dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

## Failure handling

- Renewal failed: keep serving the current certificate, fix DNS/HTTP-01 reachability,
  retry, and escalate before the critical window.
- Key compromise: revoke the certificate at the CA, issue a replacement, reload, and
  follow `INCIDENT_RESPONSE.md`. Rotate any secret that shared the host.
- Expired certificate: users see browser errors but DNS service is unaffected; replace
  immediately and record the detection gap.
