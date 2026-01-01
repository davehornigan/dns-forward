# dns-forward

DNS forwarder that listens for queries, resolves them via DoT/DoH upstreams, and
stores resolved domains/IPs in RouterOS address-list and/or a local CSV file.

## Features
- UDP/TCP DNS listener.
- Parallel DoT/DoH upstream queries; first response returned to client.
- Per-domain matching rules with subdomain depth control.
- RouterOS address-list integration with dedupe and optional TTL updates.
- Optional file output (CSV, single-column domain list).
- JSON logging with debug mode.

## Configuration
Copy `config.yaml.dist` to `config.yaml` and edit:

```yaml
upstreams:
  - udp://1.1.1.1
  - tls://dns.google
  - https://dns.google/query
fallbackUpstreams:
  - tls://dns.quad9.net
  - https://dns.quad9.net/dns-query

domains:
  - domain: google.com
    matchSubDomains: true
    maxDepth: ~
  - domain: openai.com
    matchSubDomains: true
    ttl: 10m
    recordType: host
    addressListName: openai
  - domain: example.com
    matchSubDomains: false

outputs:
  - routerOsApi:
      host: 10.0.0.1
      port: 8728
      useTLS: false
      username: admin
      password: password
      addressListName: my_resolved_domains
      ttl: ~
      updateTTL: true
      recordType: ip
  - file:
      path: ./data
      addressListName: my_resolved_domains

listenAddr: ":55353"
timeout: 5s
debug: false
```

Notes:
- DoH upstreams require a full path (e.g. `https://dns.google/query`).
- UDP/TCP upstreams use `udp://` or `tcp://` and default to port 53.
- Bare `host` or `host:port` entries default to UDP.
- `fallbackUpstreams` are only used when no primary upstream returns an address, and their answers are not written to address lists. If omitted, defaults to `udp://1.1.1.1:53`.
- `recordType: host` writes the domain itself into the address-list.
- File output writes a CSV with two columns: `domain`, `ip`. The file name is
  `<path>/<addressListName>.csv`, derived from the effective list for each domain.

## Run
```bash
go run . -config config.yaml
```

Using `air`:
```bash
make air
```

## Docker
Run the published image from GHCR:

```bash
docker run --rm -p 55353:55353/udp -p 55353:55353/tcp ghcr.io/davehornigan/dns-forward:latest
```

## License
Noncommercial. See `LICENSE`.
