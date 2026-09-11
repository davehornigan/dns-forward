# dns-forward

DNS forwarder that listens for queries, resolves them via DoT/DoH/UDP/TCP upstreams, and
emits resolved domains/IPs to one or more outputs (RouterOS address-list, CSV file, webhook).

## Features
- UDP/TCP DNS listener.
- Parallel upstream queries; first response returned to client.
- Per-domain matching rules with subdomain depth control.
- Preconfigured records per domain: known types are answered locally, unknown types go upstream.
- RouterOS address-list integration (API and REST) with dedupe (including subnet coverage) and optional TTL updates.
- File output (CSV) and webhook output.
- JSON logging with debug mode.

## Configuration
Copy `config.yaml.dist` to `config.yaml` and edit.

The config directory comes from `-config-dir`, then `CONFIG_DIR`, then the current
directory. `-config` names the file inside it (default `config.yaml`); an absolute
`-config` is used as given.

```bash
dns-forward                                  # ./config.yaml
CONFIG_DIR=/etc/dns-forward dns-forward      # /etc/dns-forward/config.yaml
dns-forward -config-dir /etc/dns-forward     # same, via flag
```

### Splitting the config
Any section can live in its own file, merged at startup. The filename names the
section and the file holds that section's bare value:

```yaml
# config.yaml
include:
  - conf.d/*.yaml
server:
  listenAddr: ":55353"
upstreams:
  - tls://dns.google
```

```yaml
# conf.d/domains.yaml
- domain: google.com
  matchSubDomains: true
```

- Only `.yaml` is accepted. Files named after a section: `server`, `upstreams`, `fallbackUpstreams`, `domains`, `outputs`. `-` and `_` are ignored, so `fallback_upstreams.yaml` works, and a `10-` style prefix orders the merge.
- `include` takes paths or globs relative to the main config's directory. A glob matching nothing is fine; a plain path that does not exist is an error. `include` only works in the main config.
- Lists are appended, so `domains` and `outputs` can be spread across several files; mappings like `server` merge key by key, with later files winning. The main config is always merged first, then includes in the order listed (globs sorted by name).

Full example:

```yaml
server:
  listenAddr: ":55353"
  timeout: 5s
  dnsTimeout: 3s
  httpTimeout: 10s
  debug: false
  writeIPWithPrefix: false
  resolveAllDomainsOnStart: false
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
  - domain: static.example.com
    matchSubDomains: true
    maxDepth: 1
    listName: static
    recordsTTL: 5m
    records:
      A: [111.111.111.111]
      AAAA: ["fe80::1"]
      TXT: hello world
  - domain: alias.example.com
    records:
      CNAME: [google.com]

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
- `server.resolveAllDomainsOnStart` resolves each configured domain at startup (A and AAAA) and emits results to outputs.
- `server.excludeSubnets` drops resolved IPs within these CIDRs before writing to outputs.

Upstreams:
- DoH upstreams require a full path (e.g. `https://dns.google/query`).
- UDP/TCP upstreams use `udp://` or `tcp://` and default to port 53.
- Bare `host` or `host:port` entries default to UDP.
- `fallbackUpstreams` are only used when no primary upstream returns an address, and their answers are not written to address lists. If omitted, defaults to `udp://1.1.1.1:53`.

Domains:
- A rule naming the queried domain exactly always wins over a rule that only covers it through `matchSubDomains`, whatever order they appear in. Among rules of the same kind the first one in the config wins, so put narrower subdomain rules above broader ones. A name that falls outside one rule's `maxDepth` can still be picked up by a broader rule further down.
- `domains[].listName` overrides the output list name for all outputs; otherwise each output uses its own `listName`.
- `domains[].outputs` controls which outputs are used by ID. If omitted or null, all outputs are used. If empty, nothing is written.
- `domains[].upstreamsOverride` overrides the primary upstream list for matching domains; if omitted, global `upstreams` are used. Fallback upstreams are always shared.
- `domains[].upstreamsBlacklist` excludes entries from the primary upstream list for matching domains. Only one of `upstreamsOverride` or `upstreamsBlacklist` may be set.
- `domains[].disableFallback` disables fallback upstreams for matching domains.

Preconfigured records:
- `domains[].records` maps a record type (`A`, `AAAA`, `CNAME`, `TXT`, `MX`, `SRV`, `NS`, ...) to one or more values. A query for a configured type is answered locally and never reaches an upstream; every other type is forwarded as usual.
- Values use zone-file syntax, with shortcuts: targets may be written without a trailing dot (`CNAME: [google.com]`) and `TXT` values are quoted automatically. A single value can be written as a scalar instead of a list.
- Records follow the rule's own matching: they answer for `domain`, and for every subdomain the rule covers when `matchSubDomains` is set, honouring `maxDepth`. Names beyond `maxDepth` are not matched by the rule at all and go upstream.
- A `CNAME` cannot be combined with other types at the same name. When an `A`/`AAAA` query hits a `CNAME`-only rule, the target is resolved upstream and the full chain is returned; the target's addresses are written to outputs under the queried name.
- `domains[].recordsTTL` sets the TTL of preconfigured records (default `5m`).
- `domains[].recordsOnly` never forwards a covered name upstream: types without a record answer `NOERROR` with no data.
- Addresses from preconfigured `A`/`AAAA` records are written to outputs like resolved ones, including at startup with `server.resolveAllDomainsOnStart`.

Outputs:
- All outputs are optional, but at least one must be configured. Every output requires a unique `id`.
- `outputs[].mode` can be `active` (default) or `passive`. Passive outputs are used only when explicitly listed in `domains[].outputs`.
- `rosApiAddressList` supports `host` with optional scheme/port; only `http`/`https` are supported. If omitted, `http` is assumed. When `useTLS` or `port` are omitted, they inherit from the host URL.
- `rosApiAddressList.connectionAttempts` controls initial connection retries (default `3`).
- `rosApiAddressList.reconnectionAttempts` controls reconnect retries after a connection failure; if omitted, it inherits `connectionAttempts`.
- `rosRestApiAddressList` sends requests over REST with basic auth. `host` supports optional scheme/port; only `http`/`https` are supported. If omitted, `http` is assumed. When `useTLS` or `port` are omitted, they inherit from the host URL. Default ports are `80` (HTTP) and `443` (HTTPS).
- `rosRestApiAddressList.connectionAttempts` controls initial connection retries (default `3`).
- `rosRestApiAddressList.reconnectionAttempts` controls retries after a REST request failure; if omitted, it inherits `connectionAttempts`.

RouterOS traffic (both `rosApiAddressList` and `rosRestApiAddressList`):
- Address lists are read in bulk: one request per list caches every entry's id, comment and remaining timeout. Addresses already on the router then cost no requests at all, and a new address costs a single write — its id comes back in the create response.
- Lists are preloaded at startup before any domain is resolved, so a deploy does not turn into one lookup per address.
- `maxConcurrentRequests` caps requests in flight (default `2`). For REST it also caps the connection pool, so the router sees a couple of long-lived connections instead of one per address. The API output uses a single connection regardless.
- `minRequestInterval` adds a minimum gap between requests (default `0`, off). Use it to spread a large batch out further.
- `refreshInterval` controls how often lists are re-read (default `5m`). One request per list, independent of how many addresses are cached.
- `restoreClearedList` puts a list back together after the router loses it — a reboot, a restored config or a manual flush (default `true`). Two conditions have to hold, so ordinary churn is never fought:
  - the list lost **at least a third** of the entries it had at the previous check. Sizes are compared rather than looking for an empty list, because the forwarder keeps writing freshly resolved addresses into the list in the meantime;
  - an entry is only re-added if **its timeout was not yet due**. Entries the router expired on schedule stay gone; entries without a timeout are always considered early. A restored entry gets the time it had left, not a fresh full timeout.

  Anything that went missing loses its cached id either way, so it is re-added on the next query for that domain even when no bulk restore runs. Set to `false` to leave the router alone entirely.
- With `updateTTL`, a timeout is only rewritten once the entry is past half its lifetime, so a busy domain does not produce a write on every query.

Outputs (continued):
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

## Development
```bash
make hooks   # enable the repo git hooks (gofmt on pre-commit)
make lint    # gofmt check and go vet
make test    # go test ./...
make help    # list all targets
```

`make hooks` points `core.hooksPath` at `.githooks`, so staged Go files are
gofmt-ed and re-staged on commit. CI runs the same checks and fails on
unformatted code.

## Docker
Run the published image from GHCR:

```bash
docker run --rm -p 55353:55353/udp -p 55353:55353/tcp ghcr.io/davehornigan/dns-forward:latest
```

## License
Noncommercial. See `LICENSE`.
