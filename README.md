# dns-forward

DNS forwarder that listens for queries, resolves them via DoT/DoH/UDP/TCP upstreams, and
emits resolved domains/IPs to one or more outputs (RouterOS address-list, CSV file, webhook).

## Features
- UDP/TCP DNS listener.
- Parallel upstream queries; first response returned to client.
- Per-domain matching rules with subdomain depth control.
- RouterOS address-list integration (API and REST) with dedupe (including subnet coverage) and optional TTL updates.
- File output (CSV) and webhook output.
- JSON logging with debug mode.

## Configuration
Copy `config.yaml.dist` to `config.yaml` and edit:

```yaml
server:
  listenAddr: ":55353"
  timeout: 5s
  dnsTimeout: 3s
  httpTimeout: 10s
  debug: false
  writeIPWithPrefix: false
  excludeSubnets:
    - 10.0.0.0/8
    - 192.168.0.0/16

upstreams:
  - tls://dns.google
  - https://dns.google/dns-query
fallbackUpstreams:
  - tls://dns.quad9.net
  - https://dns.quad9.net/dns-query
  - tcp://9.9.9.9
  - udp://1.1.1.1

domains:
  - domain: google.com
    matchSubDomains: true
    maxDepth: ~
  - domain: openai.com
    matchSubDomains: true
    listName: openai
    disableFallback: false
    upstreamsOverride:
      - tls://one.one.one.one
      - https://one.one.one.one/dns-query
  - domain: example.com
    matchSubDomains: false
    upstreamsBlacklist:
      - https://dns.google/dns-query

outputs:
  - type: rosApiAddressList
    id: ros_main
    mode: active
    host: 10.0.0.1
    port: 8728
    useTLS: false
    username: admin
    password: password
    listName: my_resolved_domains
    ttl: ~
    updateTTL: true
    recordType: ip
    connectionAttempts: 3
    reconnectionAttempts: 3
  - type: rosRestApiAddressList
    id: ros_rest
    mode: passive
    host: http://10.0.0.2
    port: ~
    useTLS: false
    username: admin
    password: password
    listName: my_resolved_domains_rest
    ttl: ~
    updateTTL: true
    recordType: ip
    connectionAttempts: 3
    reconnectionAttempts: 3
  - type: file
    id: file_main
    mode: active
    path: ./data
    listName: my_resolved_domains
    format: csv
  - type: webhook
    id: webhook_main
    mode: active
    method: POST
    url: https://example.com/dns-webhook
    listName: my_resolved_domains
```

## Config Details
Server:
- `server.timeout` is the overall time budget for a DNS request.
- `server.dnsTimeout` applies to upstream DNS queries.
- `server.httpTimeout` applies to webhook and RouterOS API requests.
- `server.writeIPWithPrefix` writes resolved IPs as `/32` (IPv4) or `/128` (IPv6).
- `server.excludeSubnets` drops resolved IPs within these CIDRs before writing to outputs.

Upstreams:
- DoH upstreams require a full path (e.g. `https://dns.google/query`).
- UDP/TCP upstreams use `udp://` or `tcp://` and default to port 53.
- Bare `host` or `host:port` entries default to UDP.
- `fallbackUpstreams` are only used when no primary upstream returns an address, and their answers are not written to address lists. If omitted, defaults to `udp://1.1.1.1:53`.

Domains:
- `domains[].listName` overrides the output list name for all outputs; otherwise each output uses its own `listName`.
- `domains[].outputs` controls which outputs are used by ID. If omitted or null, all outputs are used. If empty, nothing is written.
- `domains[].upstreamsOverride` overrides the primary upstream list for matching domains; if omitted, global `upstreams` are used. Fallback upstreams are always shared.
- `domains[].upstreamsBlacklist` excludes entries from the primary upstream list for matching domains. Only one of `upstreamsOverride` or `upstreamsBlacklist` may be set.
- `domains[].disableFallback` disables fallback upstreams for matching domains.

Outputs:
- All outputs are optional, but at least one must be configured. Every output requires a unique `id`.
- `outputs[].mode` can be `active` (default) or `passive`. Passive outputs are used only when explicitly listed in `domains[].outputs`.
- `rosApiAddressList` supports `host` with optional scheme/port; only `http`/`https` are supported. If omitted, `http` is assumed. When `useTLS` or `port` are omitted, they inherit from the host URL.
- `rosApiAddressList.connectionAttempts` controls initial connection retries (default `3`).
- `rosApiAddressList.reconnectionAttempts` controls reconnect retries after a connection failure; if omitted, it inherits `connectionAttempts`.
- `rosRestApiAddressList` sends requests over REST with basic auth. `host` supports optional scheme/port; only `http`/`https` are supported. If omitted, `http` is assumed. When `useTLS` or `port` are omitted, they inherit from the host URL. Default ports are `80` (HTTP) and `443` (HTTPS).
- `rosRestApiAddressList.connectionAttempts` controls initial connection retries (default `3`).
- `rosRestApiAddressList.reconnectionAttempts` controls retries after a REST request failure; if omitted, it inherits `connectionAttempts`.
- File output `format` can be `csv` (default), `ipset`, or `nftset`. CSV writes `domain,ip` rows to `<path>/<listName>.csv`. `ipset` and `nftset` write dnsmasq rules to `<path>/<listName>.conf`.
- `ipset` example: `ipset=/showip.net/LIST_NAME`
- `nftset` example: `nftset=/showip.net/4#inet#fw4#LIST_NAME`
- Webhook output sends JSON: `{"list":"name","domain":"example.com","addresses":["1.2.3.4"]}`. Method defaults to `POST`. For `GET`, data is sent as query params: `list`, `domain`, and repeated `addresses[]`. `listName` is required.

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
