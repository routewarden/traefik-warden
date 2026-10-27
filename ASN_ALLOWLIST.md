# ASN allowlisting

ASN lookup uses a local JSON routing snapshot, loaded and validated at startup.
No DNS or HTTP request is made while handling traffic. Configure ASN identifiers
as strings, either `"64500"` or `"AS64500"` (case insensitive). Both IPv4 and IPv6
are supported, including IPv4-mapped client addresses.

## Build the routing snapshot

Convert locally downloaded GeoLite2/GeoIP2 ASN Blocks CSV files with Python 3:

```sh
python3 scripts/build-asn-db.py -o /etc/routewarden/asn.json \
  GeoLite2-ASN-Blocks-IPv4.csv GeoLite2-ASN-Blocks-IPv6.csv
```

The database format is an object mapping ASN identifiers to CIDR arrays. This
illustrative data uses documentation ASNs and addresses:

```json
{
  "64500": ["192.0.2.0/24", "2001:db8::/32"],
  "64501": ["2001:db8:1::/48"]
}
```

Keep routes for other ASNs in the snapshot: longest-prefix matching ensures a
more specific route owned by another ASN does not inherit an allowed parent's
bypass. Conflicting origins for the same prefix are rejected. Unknown addresses
never match. Invalid identifiers, unreadable or malformed databases, and allowed
ASNs with no routes prevent initialization. Empty allowlists disable this feature.

The snapshot is held in memory. Replace the file and recreate the middleware instance or fully restart the
daemon to refresh routing data; existing instances keep their original snapshot.
Paths are resolved by the process, so mount the file into each proxy container.

## HTTP behavior

An ASN match bypasses request inspection, just like an existing IP allowlist match.
A non-match continues normal inspection; it does not reject otherwise valid requests.
Only the client IP is used; client-provided ASN headers are never trusted.
Without `trustedProxies`/`trusted_proxies`, ASN lookup uses the socket peer. Behind
a proxy, configure trusted proxy CIDRs and have that proxy sanitize forwarding
headers. Existing IP-allowlist header behavior remains unchanged.

## Traefik configuration

```yaml
http:
  middlewares:
    warden:
      plugin:
        routewarden:
          allowedASNs: ["64500"]
          asnDB: /etc/routewarden/asn.json
          trustedProxies: ["10.0.0.0/8"]
```

Shared JSON `configFile` policies also accept `allowed_asns` and `asn_db` aliases.
