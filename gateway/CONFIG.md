# Gateway configuration

Every setting of the gateway is an environment variable, read once at startup; the routing
policy can come from a configuration file instead (see below). Defaults are the values in the
code; "unset" means the variable is absent or empty unless a row says otherwise. A malformed
value is a startup error unless a row says it falls back to the default.

## Configuration file

The routing policy (the variables below) can be written as one TOML file instead, the same
policy by construction: the file is turned into the values of the variables it stands for,
which the same parsers read. Everything else (addresses and stores, identity, sizing, keys and
other secrets) stays in the environment. [`config.example.toml`](config.example.toml) shows
every key.

| Variable | Default | Meaning |
|---|---|---|
| `CONFIG_SOURCE` | `env` | `env`: the policy variables of the environment, no file is read. `compare`: the environment stays in force; the file is loaded and checked too, the two policies are compared (`ohttp_config_compare_match` 1 or 0, and one log line naming the differing keys, never a value); a file that does not load is logged and counts as 0, it never stops the gateway. `file`: the file is in force; the policy variables of the environment are ignored, with one warning naming those that are set; a file that does not load (or a secret it names that does not resolve) stops the gateway at startup. Any other value is a startup error. |
| `GATEWAY_CONFIG_FILE` | unset | Path of the file (`--config <path>` wins). Read with `CONFIG_SOURCE=compare` or `file` and by `--check-config`. |

The policy variables are `GATEWAY_HOSTS`, `BACKENDS`, `BACKENDS_POLICY`,
`BACKENDS_POLICY_DEFAULT`, `BACKEND_HEADERS`, `FLEXA_ALIAS`, `NEAR_ALIAS`,
`THIRD_PARTY_CACHE_ROUTES`, `THIRD_PARTY_RATE_LIMITS`, `THIRD_PARTY_QUERY_RULES`,
`THIRD_PARTY_QUERY_VALUE_SOURCES`, `THIRD_PARTY_HOSTS_PUBLISH`, `THIRD_PARTY_HOSTS_MAX_AGE_SECS`,
`REPLAY_READ_ROUTES`, `REPLAY_ONE_SIDED_WRITE_ROUTES`, `DYNAMIC_HOST_SOURCES`,
`DYNAMIC_HOSTS_DENY_CIDRS`, `RELAY_SECRET_ON_KEY_CONFIG` and `PROXY_ALLOW_SUFFIXES` (read by no
code; the file has no key for it, `proxy_allow_suffixes` is accepted with a warning for one
release).

The file (`schema = 1`; an unknown key is an error; a key a release removed is accepted with a
warning for one release):

- top level: `gateway_hosts` (`GATEWAY_HOSTS`), `backends_policy_default` (`allow` or `deny`),
  `relay_secret_on_key_config`;
- `[secrets]`: `name = { env = "VAR" }` or `name = { file = "/path" }`: a regular file of at
  most 64 KiB, its content without one final `\n` or `\r\n` (no permission of the file is
  checked). A value that is empty, blank, or holds a line break or another control character
  does not resolve. A secret file is opened without blocking and must be a regular file (a
  FIFO, a directory or a device is refused). A header names a secret; every declared secret
  must resolve (used or not) where secrets are required. Secret values and header values are
  never logged or printed, not even in an error; an error about the file gives the position
  and kind of the problem with quoted values removed, and may name keys, aliases, hosts and
  route patterns of the policy;
- `[integrations.<label>]`: one `BACKENDS` alias: `alias`, `upstream`, `kind` (`generic`, the
  default; `flexa` for `FLEXA_ALIAS`; `near` for `NEAR_ALIAS`; `cmc` and `swapkit`: generic
  providers that must have a header credential and a query rule on every route), and its rules:
  `routes` (`BACKENDS_POLICY`; leave it out for no entry), `headers` (`BACKEND_HEADERS`:
  `{ name, value, secret }`, `{secret}` in `value` replaced by the secret), `cache`
  (`THIRD_PARTY_CACHE_ROUTES`, `METHOD /path@TTL`; each must be within `routes`), `rate_limit`
  (`THIRD_PARTY_RATE_LIMITS`), `query_rules`, `read_routes` (`REPLAY_READ_ROUTES`),
  `one_sided_write_routes`. Two integrations with one alias, or an alias that is a gateway host,
  are errors;
- `[hosts."<authority>"]`: the same rules for an authority that is no alias: a gateway host's
  `routes` and `headers`, the pseudo authority `lwd` of the replay routes;
- `[value_sources.<name>]`: `alias`, `route` (`GET /path`), `pointer`, `refresh_secs`,
  `fallback`;
- `[dynamic_hosts]`: `deny_cidrs`, `sources` (the sources of `DYNAMIC_HOST_SOURCES` as tables);
- `[host_list]`: `publish`, `max_age_secs`.

Every list entry keeps the grammar of its variable (a separator of that grammar inside an entry
is an error). Every startup check of the variables applies to the file.

Command line (`zodl-ohttp-gateway [--config <path>] [ACTION]`; no action serves, as before;
`backfill` is unchanged):

| Action | Effect | Exit |
|---|---|---|
| `--check-config [--secrets=require\|skip]` | Load and check the file (`--config` or `GATEWAY_CONFIG_FILE`), resolve its secrets (`require`, the default) or not (`skip`), and run the startup checks on the policy it stands for. Prints `config OK: <path> (schema 1, digest <16 hex>, ...)` or the error on stderr. | 0 valid, 1 not |
| `--print-effective-config` | The policy in force (`CONFIG_SOURCE`: the file for `file`, checked first as by `--check-config --secrets=skip`; else the environment, with a note on stderr when a file is given) as canonical JSON: sorted keys, header values `<redacted>`, no secret names, kinds as declared. | 0, 1 on error |
| `--export-config` | The file equivalent to the environment's policy, checked before it is printed (it parses, passes `--check-config --secrets=skip` and is the environment's policy). A header value becomes a secret reference: to the variable it equals (or equals after `Bearer ` or `Basic `), else to a new variable for the whole value (named on stderr) that the operator sets. An environment no file can express is an error naming the key. | 0, 1 on error |

An unknown option, or two actions, exit with 2. `backfill` as the first argument ignores
everything after it, as before, and reads the environment's policy whatever `CONFIG_SOURCE`
says.

`ohttp_config_info{source,digest}` is 1 on every serving process: the source (`env`, `compare`,
`file`) and the first 16 hex digits of the SHA-256 of the canonical behaviour form of the policy
in force (keyed kinds as `generic`, method tokens in upper case, gateway hosts and deny CIDRs
as sorted sets, no dynamic sources as an empty list, defaults of unset keys written out), the
same for a file and the environment it stands for; it is not the hash of the JSON
`--print-effective-config` prints.

## Mode, network, listener

| Variable | Default | Meaning |
|---|---|---|
| `GATEWAY_MODE` | `ohttp` | `ohttp`: only Encapsulated Requests on `POST /gateway`; any other path or method answers 426. `proxy`: additionally a plaintext gRPC passthrough to lightwalletd on every other path (testing only, no privacy). |
| `NETWORK` | `mainnet` | `mainnet` or `testnet`: the network label of logs and metrics, the `network` the signed key configuration is bound to, and the Sapling activation height used by the permanent tier and as the lowest height of the pinned backfill (419200 for `mainnet`; 280000, the testnet one, for `testnet` and any other label). If unset and `GATEWAY_MODE` is `mainnet` or `testnet`, that value is used. |
| `PORT` | `8080` | Public listener (`/gateway`, `/ohttp-configs`, `/ohttp-configs/signed`, `/healthz`, `/health/startup`). The observability listener is set by `INTERNAL_BIND_ADDR`. |
| `INTERNAL_BIND_ADDR` | `0.0.0.0:9090` | Bind address of the internal observability listener (`/health`, `/health/live`, `/health/ready`, `/metrics`): an IP address (port 9090) or `IP:port` (`[v6]:port` for IPv6). The default listens on all interfaces so that Prometheus on other hosts can scrape it. The internal port serves metrics and health and has no authentication: it should not be reachable from untrusted networks (restrict it by firewall or security group, or bind it to a private or loopback address). An unparsable value stops the gateway at startup. |
| `HEADER_READ_TIMEOUT_SECS` | `300` | Request header read timeout of both listeners (HTTP/1.1 only). Also bounds how long a keep-alive connection may sit idle, so it must exceed the idle timeout of every proxy that reuses connections to the gateway; values from 1 to 130 are refused, `0` disables it. |
| `RUST_LOG` | `info` | `tracing` filter for the JSON logs (`trace`, `debug`, `info`, `warn`, `error`, or per-module directives under the crate's target `zodl_ohttp_gateway`, e.g. `info,zodl_ohttp_gateway::proxy=debug`). |
| `LOG_OUTER_HEADER_NAMES` | `false` | `1`/`true`: log the names (never the values) of the outer headers each request arrives with. A privacy audit aid. |

## Relay authentication

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_SECRET` | unset | Comma-separated list of accepted `X-Relay-Secret` values. An entry is `name=secret` (`name`: 1 to 32 characters of `a-z0-9-`, used as the `relay` label of metrics and logs) or a bare secret, named `relay-<position>`. A remainder of `=` only is base64 padding, not a name. Duplicate names or duplicate secrets are a startup error. Required in `ohttp` mode unless `ALLOW_UNAUTHENTICATED_RELAY` is set. Presented secrets are compared as SHA-256 digests against every entry in constant time. |
| `RELAY_SECRETS` | unset | Same as `RELAY_SECRET`, same grammar. Setting both is a startup error. |
| `ALLOW_UNAUTHENTICATED_RELAY` | `false` | `1`/`true`: run `ohttp` mode without relay secrets. Insecure: only for local tests, or behind an edge that admits authorised relays alone. Logged as a warning. |
| `RELAY_SECRET_ON_KEY_CONFIG` | `off` | `require`: `GET /ohttp-configs` and `GET /ohttp-configs/signed` also need exactly one valid `X-Relay-Secret` (otherwise 401), so the key configuration can only be fetched through a relay. Needs relay secrets. Before switching it on, check that every relay forwards the header on these GETs. |

## Keys

| Variable | Default | Meaning |
|---|---|---|
| `HPKE_KEYS` | unset | Advertised HPKE keys, `<key_id>:<hex X25519 private key>,...`, preferred first. Takes precedence over `HPKE_PRIVATE_KEY`. |
| `HPKE_PRIVATE_KEY` | unset | A single advertised key (hex X25519 private key, 32 bytes), with id `HPKE_KEY_ID`; ignored when `HPKE_KEYS` is set. In `ohttp` mode one of `HPKE_KEYS` or `HPKE_PRIVATE_KEY` is required: the gateway never generates a key and refuses to start without one. In `proxy` mode no key is loaded and the key-configuration endpoints answer 503. |
| `HPKE_KEY_ID` | `1` | Key id (0 to 255) of `HPKE_PRIVATE_KEY`. |
| `HPKE_ACCEPT_ONLY_KEYS` | unset | Keys accepted for decapsulation but not published, same format as `HPKE_KEYS`. Used during a rotation. Key ids must be distinct across both lists. |
| `CONFIGS_SIGNING_SEED_HEX` | unset | Ed25519 seed (64 hex characters) that signs `/ohttp-configs/signed`. Unset: that endpoint answers 503. An invalid seed is a startup error in `ohttp` mode. |

## Routing and backends

| Variable | Default | Meaning |
|---|---|---|
| `LWD_ADDR` | `localhost:9067` | lightwalletd gRPC address (`host:port`, plaintext HTTP/2). |
| `GATEWAY_HOSTS` | **required** (`ohttp` mode) | The gateway's own host names (comma-separated, lower-cased, port stripped). An inner request whose `:authority` is one of them goes to lightwalletd; any other authority that is not a `BACKENDS` alias gets an inner 403 `unknown authority`. In `ohttp` mode the gateway refuses to start when it is unset or empty. An empty `:authority` is always refused. |
| `BACKENDS` | unset | Third-party aliases, `alias=https://base-url,...`. An inner request whose `:authority` equals an alias (case-insensitive) is sent to that base URL. `lwd` is reserved. `http://` is accepted for tests. |
| `BACKEND_HEADERS` | unset | Headers set on requests to an alias, `alias=Header-Name:value,...` (e.g. an API key). Of the client's inner headers only `content-type`, `grpc-timeout`, `grpc-encoding` and `grpc-accept-encoding` are forwarded and, for `FLEXA_ALIAS` only, the headers listed under `FLEXA_PUBLISHABLE_KEY` and `Authorization`; client cookies never reach a backend. |
| `BACKENDS_POLICY` | unset | Allowed operations per authority, `alias=METHOD /path,METHOD /prefix/*;alias2=...` (`*` method = any; `/*` suffix = prefix match on a segment boundary). A request to an alias without an entry is refused with inner 403 unless `BACKENDS_POLICY_DEFAULT=allow`. An entry for a `GATEWAY_HOSTS` host restricts the lightwalletd routes too. An entry for any other authority is never applied (warned). |
| `BACKENDS_POLICY_DEFAULT` | deny | `allow`: aliases without a `BACKENDS_POLICY` entry accept every operation. Insecure. |
| `THIRD_PARTY_QUERY_RULES` | unset | Allowed query strings per exact route of a `BACKENDS` alias, `alias=METHOD /path?name=VALUE&name2=VALUE2,METHOD /path?;alias2=...` (e.g. `prices.example=GET /v1/quotes?symbol=ZEC&convert={in:USD|EUR}`). VALUE is a literal (exact, case-sensitive), `{in:A|B|C}` (exactly one of 1 to 256 distinct alternatives, each 1 to 64 characters of `[A-Za-z0-9._~-]`), `{upper:MIN-MAX}` (MIN to MAX ASCII uppercase letters, MAX at most 32) or `{from:name}` (exactly one value of the current list of `THIRD_PARTY_QUERY_VALUE_SOURCES` source `name`, which must read the same alias); prefer `{in:...}` or `{from:...}` over `{upper:...}` for upstreams the gateway sends a credential to. `/path?` = no query string (an empty one too). A request with the rule's alias, method and exact path must carry exactly the rule's parameters, in the rule's order, each once, no other, every value matching byte for byte on the raw (percent-encoded) query, so a value with `%` or `+` matches only a byte-identical literal; `,` and `;` cannot appear in a literal (write the percent-encoded form, which then must be sent byte for byte). The query is never rewritten: the string checked is the cache key and the upstream request. With several rules for one route any one suffices; one request reads each source list once. Otherwise inner 403 `policy denied` (log reason `query not allowed`, counted in `ohttp_policy_denied_total`), before `THIRD_PARTY_CACHE_ROUTES` and `THIRD_PARTY_RATE_LIMITS`: a refused request reads no cache entry and spends no upstream call. This bounds, but does not remove, cache misses: the admitted value set bounds the distinct cache keys of a route (`/path?` and `/path` are two keys), answers that are not a 200 (or never arrive) are not cached, and `THIRD_PARTY_RATE_LIMITS` still bounds the upstream calls those cost. Startup error for any other pattern, a `{from:}` naming no source or a source of another alias, a prefix path, a path the request side would refuse, an alias not in `BACKENDS` (gateway hosts and dynamic hosts get no query rules), a route its `BACKENDS_POLICY` entry does not allow, any `BACKENDS_POLICY` entry of the alias that contains `?`, and a `BACKENDS_POLICY` entry of the alias that admits a rule's path as a `*`-method or `/*` prefix entry or with another method that has no rule (those would reach the path with any query). Routes without a rule are not affected. |
| `THIRD_PARTY_QUERY_VALUE_SOURCES` | unset | Allowed-value lists for `{from:name}`, read from the upstream: `name=alias GET /path#/json/pointer@REFRESH_SECS[@fallback=A|B|C];name2=...` (e.g. `fiat=prices.example GET /v1/fiat/map#/data/*/symbol@21600@fallback=USD|EUR`; `name` is `[a-z0-9_-]{1,32}`; no `@` or `;` in the path or pointer). Only rules of the same alias may use a source. Each process fetches each source itself: first after a random 0 to 5 s after startup (in the background, never delaying it), then every `REFRESH_SECS` (300 to 604800); after a failure again in 60 s, doubling up to `REFRESH_SECS`; every wait +-10 %. Processes keep their own lists, so they can differ for up to `REFRESH_SECS`. The fetch is a `GET` sent through the forwarder like any request to the alias (its `BACKENDS` base URL and `BACKEND_HEADERS` credential, the forwarder's permits, counted in the upstream metrics and logged like other forwards; a forwarder at its permit limit answers a non-200, which is a `status` failure and retried), within 10 s, reading at most 256 KiB; it does not use `THIRD_PARTY_CACHE_ROUTES` and does not count against `THIRD_PARTY_RATE_LIMITS` (its upstream cost is one call per source per process per `REFRESH_SECS`, more while failing, at most about one a minute). The pointer is RFC 6901, a segment `*` iterates an array (at most two); each selected item must be a JSON string of 1 to 64 characters of `[A-Za-z0-9._~-]`, others are skipped (`ohttp_query_value_source_skipped_total`); duplicates are merged; more than 2048 values rejects the document (the walk stops there). **Failure semantics:** a refresh that fails (transport error or timeout, a status other than 200, a body over 256 KiB, not JSON, the pointer not found, no valid value, too many values, or fewer valid values than half the list admitted now, rounded up, at least one) changes nothing: the last accepted list stays, so a list never becomes empty. A list smaller than half the admitted one is never accepted by a refresh, however often it is fetched: the admitted list is held until a restart (with a smaller or no fallback) or a configuration change. Alert on `ohttp_query_value_source_refresh_total{result="too_few"}` and on a stale `ohttp_query_value_source_last_success_timestamp_seconds` (0 = never succeeded). Before the first accepted fetch the `fallback` values (same character rule) are admitted; the first accepted list replaces the fallback (it is not merged), and the half rule compares with the fallback then. Without a fallback `{from:name}` admits nothing (inner 403 `policy denied`) until then. A failed refresh logs its result, HTTP status and error, never the body or values; an accepted change logs counts only. Startup error for a malformed entry, a duplicate name, an alias not in `BACKENDS`, a source no `{from:}` uses, a route the alias's `BACKENDS_POLICY` does not allow through an exact `GET` entry (the same checks as for `THIRD_PARTY_QUERY_RULES` routes), and a source request a query rule of its route would refuse. Unset or blank: no source; a value that is not UTF-8 is a startup error. |
| `PROXY_ALLOW_SUFFIXES` | unset | Parsed into the configuration (comma-separated domain suffixes, lower-cased) but not used for routing: only exact `BACKENDS` aliases and `GATEWAY_HOSTS` are ever forwarded. Kept for configuration compatibility; setting it has no effect. |
| `FLEXA_ALIAS` | unset | The `BACKENDS` alias whose upstream is the Flexa API. Requests to it get the Flexa header handling (see `FLEXA_PUBLISHABLE_KEY`), a `text/event-stream` answer is streamed, and its answers are never cached. Unset: no alias gets this handling. |
| `FLEXA_PUBLISHABLE_KEY` | unset | Publishable key for `FLEXA_ALIAS`. It replaces only the apps' placeholder credential (`Authorization: Basic` of `:publishable_live_zodl_gateway_placeholder`); any other `Authorization` value passes through. That alias also forwards `accept`, `flexa-app`, `flexa-version`, `client-trace-id` and `last-event-id`. |
| `NEAR_ALIAS` | unset | The `BACKENDS` alias of the NEAR Intents 1Click API. Only its public `GET /v0/tokens` may appear in `THIRD_PARTY_CACHE_ROUTES` (startup error otherwise). |
| `THIRD_PARTY_CACHE_ROUTES` | unset | Cached third-party routes, `alias=METHOD /path@TTL_SECS,...;alias2=...`. Only `GET` answers with status 200 are stored; concurrent misses for one key are coalesced. Never for `FLEXA_ALIAS`. Needs the cache Redis. |
| `THIRD_PARTY_RATE_LIMITS` | unset | Per-alias cap on upstream calls (cache hits do not count), `alias=REQUESTS/WINDOWs,...` (e.g. `prices.example=120/60s`). Over the cap the inner answer is 429 with `retry-after`. Fixed window, per process. |
| `CACHE_KEY_BACKEND` | `LWD_ADDR` | Backend name written into cache keys. For an instance that fills the cache from a different lightwalletd address than the serving gateways use. |

### Dynamic third-party hosts

A service whose operators publish their server list in a JSON document can add a server at any
time. With a static `BACKENDS` map the gateway refuses the new host until it is redeployed. A
*dynamic host source* reads such a document periodically and serves the hosts it lists, like a
`BACKENDS` alias whose target is the host itself: a listed `https://vote.example.org` makes the
inner `:authority` `vote.example.org` go to `https://vote.example.org<path>`, on the routes of
its list only. Off unless `DYNAMIC_HOST_SOURCES` is set.

| Variable | Default | Meaning |
|---|---|---|
| `DYNAMIC_HOST_SOURCES` | unset | A JSON array of at most 8 sources (fields below). Unset or empty: no dynamic host. A malformed value, an unknown field or a value out of range is a startup error. |
| `DYNAMIC_HOSTS_MAX_DOCUMENT_BYTES` | `262144` | Largest source document read (1024..=8388608). A larger one is refused while it is read (`result="too_large"`). |
| `DYNAMIC_HOSTS_FETCH_TIMEOUT_SECS` | `10` | Network time of one refresh of one source in total: fetching the document and, when configured, its signature, each with connect, head and body (1..=60). Checking and applying the document is not part of it. |
| `DYNAMIC_HOSTS_DENY_CIDRS` | unset | Address blocks no dynamic host is ever connected to, besides the non-public ones: comma-separated `address/prefix` (IPv4 or IPv6; an IPv4 block also covers its IPv4-mapped and NAT64 forms). For the operator's own public ranges and anything else that trusts the gateway's addresses. An IPv4 block written in IPv4-mapped IPv6 form (prefix 96 or longer) is that IPv4 block; any other IPv6 block covers IPv6 addresses only. Read once, when the process starts. A malformed entry is a startup error. |
| `THIRD_PARTY_HOSTS_PUBLISH` | `off` | The host list for wallets (below): `off`, `dynamic` (the hosts of the sources) or `all` (the `BACKENDS` aliases too). Any other value is a startup error. |
| `THIRD_PARTY_HOSTS_MAX_AGE_SECS` | `300` | How long a wallet may use the host list before it asks again (30..=86400): `max_age_secs` in the document and `cache-control: max-age`. |

Fields of a source:

| Field | Default | Meaning |
|---|---|---|
| `name` | required | 1 to 32 characters of `a-z`, `0-9`, `-`, `_`; unique. The `source` metric label; the hosts' `backend` label is `dynamic:<name>`. |
| `url` | required | The document, `https://` only. Fetched with `GET`; only a `200` counts, a redirect is not followed. This URL (and `signature_url`) is the operator's choice and is fetched with the ordinary client: it may be an internal mirror. The public-address rule below is for the hosts the document lists. |
| `refresh_secs` | `60` | Refresh interval (30..=86400), with ±10 % jitter. After a failed refresh the next attempt comes after `min(refresh_secs, 60)` s, with the same jitter. |
| `lists` | required | 1 to 8 lists: `pointer` (RFC 6901 JSON pointer to an array), `url_field` (the field of each element that holds the URL; omitted: the elements are the URL strings), `routes` (what the hosts of this list may be asked, `METHOD /path,METHOD /prefix/*` as in `BACKENDS_POLICY`; required), `read_routes` (of those, the ones without a side effect, in the same syntax; default none, so every request is a WRITE for the replay check). A host in several lists may be asked what any of them allows; a request is a READ only when every list that allows it also has it in `read_routes`, so a `read_routes` entry never reaches beyond its own list's `routes`. `REPLAY_READ_ROUTES` and `REPLAY_ONE_SIDED_WRITE_ROUTES` are not consulted for a dynamic host. |
| `host_suffixes` | none | When set, a listed host must equal one of these names or be a subdomain of one. |
| `allow_ports` | none | Ports accepted besides 443. A host on another port is addressed as `host:port`. |
| `max_hosts` | `64` | Hosts per document (1..=256). A document that lists more is refused whole (`result="invalid"`). |
| `max_new_hosts_per_refresh` | `8` (at most `max_hosts`) | Hosts not served yet that one refresh admits, in document order; the rest wait for the next refreshes (`result="partial"`, `ohttp_dynamic_hosts_held`). The first document a process accepts is bounded by `max_hosts` only. |
| `rate_limit` | none | Cap on upstream calls per host, `REQUESTS/WINDOWs` as in `THIRD_PARTY_RATE_LIMITS`; over it the inner answer is 429 with `retry-after`. Per process. The window and the in-flight count belong to the host for as long as the source lists it, whatever happens to its routes; a host that leaves the list and returns starts anew. |
| `signature_url`, `signature_keys` | none | Together: the document is accepted only with a detached Ed25519 signature over its exact bytes, fetched from `signature_url` (the base64 text of the 64 bytes, or the 64 raw bytes), that verifies under one of `signature_keys` (base64 public keys). Else `result="signature"`. The signature proves who wrote the document, not that it is the newest one: an older signed document is accepted again. |

```
DYNAMIC_HOST_SOURCES=[{"name":"servers","url":"https://config.example.org/dynamic.json",
  "lists":[{"pointer":"/api_servers","url_field":"url","routes":"GET /*,POST /*","read_routes":"GET /*"},
           {"pointer":"/query_endpoints","url_field":"url","routes":"GET /root,POST /v1/query"}],
  "rate_limit":"600/60s"}]
```

Rules:

- **Static configuration wins.** A listed host that is a `BACKENDS` alias, a `GATEWAY_HOSTS`
  name, the host of a `BACKENDS` target or of `LWD_ADDR` is never served from a source
  (`ohttp_dynamic_hosts_shadowed`): what the static configuration forwards to stays reachable
  only under its alias, with that alias' policy, cache and limits. Of two sources that list
  one host, the first in the array serves it.
- A listed URL must be `https://host[:port]` and nothing more: no userinfo, no path (a single
  `/` is accepted), query or fragment. The host is a DNS name of at least two labels whose last
  label is alphabetic (or `xn--`) and not a special-use name (`localhost`, `local`, `internal`,
  `arpa`, `test`, `invalid`, `onion`, `lan`, `home`, `corp`), or a public dotted-quad IPv4
  address; IPv6 literals are not accepted. An entry that fails is skipped
  (`ohttp_dynamic_hosts_rejected`) and the others are served: a host whose entry became
  invalid is no longer served, like a host that was removed. A document whose lists hold more
  than four times `max_hosts` entries in total, valid or not, is refused whole (`invalid`).
- **Only public addresses are connected to.** Requests to dynamic hosts use their own HTTPS
  client, whose resolver drops every address that is not globally routable (loopback, private,
  shared, link-local including the instance metadata address, unique local, multicast,
  documentation, reserved, and the IPv4-mapped, NAT64, 6to4 forms of those) and every address
  in `DYNAMIC_HOSTS_DENY_CIDRS` before a connection is made. A host name without such an
  address fails to connect (inner 502), whatever it resolved to when it was listed. A host
  listed as an IPv4 literal is checked when it is listed and again for every request. TLS
  certificates are verified as for `BACKENDS`.
- A dynamic host gets only the routes of its list: `BACKENDS_POLICY_DEFAULT=allow` does not
  apply. It never receives `BACKEND_HEADERS` values or the `FLEXA_ALIAS` handling, and
  `THIRD_PARTY_CACHE_ROUTES` and `THIRD_PARTY_RATE_LIMITS` do not apply to it. The gateway's
  `X-Request-Id` is not sent to it. The global and per-backend in-flight limits, response size
  limit and timeouts apply as to any third party; without the source's `rate_limit` there is
  no cap on the call rate, only on calls in flight.
- **Last-known-good.** A failed fetch, a status other than 200, an oversized or unparsable
  document, a missing list, a document without a valid host, more hosts than `max_hosts` or a
  signature that does not verify change nothing: the hosts of the last accepted document stay
  served, and the refresh is counted by `result`. A source cannot empty its list. (Single
  invalid entries of an otherwise valid document are skipped, see above.)
- A refresh replaces the served set in one step. A request reads the served set once, before
  its replay check, and uses that entry for its replay class, policy, limits, labels and the
  forward; requests in flight to a host that was removed complete.
- Before it serves, a starting gateway attempts one refresh per source, all at once. The
  network waits of a refresh end after `DYNAMIC_HOSTS_FETCH_TIMEOUT_SECS`; checking and
  applying a document (of at most `DYNAMIC_HOSTS_MAX_DOCUMENT_BYTES`) comes on top. Leave room
  for both in the startup probe's budget; a source that does not answer never stops the start, its hosts are missing until
  it does. Nothing is kept across restarts, so hosts that must be
  reachable while a source is down belong in `BACKENDS`. The same holds when a source's
  document stops listing any valid host: replicas that accepted hosts from it before keep
  them (`result="empty"`), a replica started since then has none, until the source lists
  hosts again or the older replicas restart.
- Every process refreshes on its own. While the source answers, replicas differ for about one
  refresh interval at most (longer while hosts are held by `max_new_hosts_per_refresh`); while
  it does not, each keeps what it last accepted, and a replica started meanwhile has none, for
  as long as the outage lasts. A request for a host a replica does not serve gets the inner
  403 `unknown authority`. A replica without the feature refuses every
  dynamic host, so when moving hosts from `BACKENDS` to a source, remove the static entries
  only after every replica runs with the source.
- In `proxy` mode (`GATEWAY_MODE=proxy`, no OHTTP) a dynamic host is selected by the request's
  `Host`, exactly like a `BACKENDS` alias, under the same rules as above.

Published server lists are usually not signed: where such a document carries signatures, they
tend to cover other entries of it, not the server lists and not the document as a whole. So without `signature_url`
the list's only authenticity is TLS to `url`. What a wrong or compromised document can then add
is bounded by the rules above: at most `max_hosts` public HTTPS hosts, at most
`max_new_hosts_per_refresh` more per refresh, reachable on the configured routes only, without
any credential. Public is not the same as harmless: a listed host can be any public service,
including one that trusts the gateway's egress addresses, or the operator's own public
(IPv4 or IPv6) addresses: list those in `DYNAMIC_HOSTS_DENY_CIDRS`. Where the publisher's
hosts share domains, set `host_suffixes`; a source with neither `host_suffixes` nor a signature is logged
at startup. Alert on `ohttp_dynamic_hosts_held > 0` and on refresh results other than `ok` and
`unchanged`. The growth cap does not bound the first document a process accepts (a restart
loads up to `max_hosts` at once; logged when it exceeds `max_new_hosts_per_refresh`), so also
watch `ohttp_dynamic_hosts` itself.

#### The host list for wallets

Wallets refuse to send a third-party request through the gateway unless they know the gateway
carries its host. With `THIRD_PARTY_HOSTS_PUBLISH` the gateway tells them: the inner request
`GET /ohttp-gateway/v1/third-party-hosts` with a `GATEWAY_HOSTS` name as `:authority` (through
OHTTP only; the path does not exist on the public listener) is answered by the gateway itself:

```json
{"version":1,"revision":"5b0c1d9e7a3f2c44","scope":"all","max_age_secs":300,
 "hosts":[{"host":"vote.example.org","routes":["GET /*","POST /*"]}]}
```

`host` is what a wallet puts in `:authority`; nothing else about a backend is published (no
alias target, no injected header, no source). `routes` are the operations forwarded, in
`BACKENDS_POLICY` syntax. Under `all`, a `BACKENDS` alias is listed with its `BACKENDS_POLICY`
rules; one without rules only under `BACKENDS_POLICY_DEFAULT=allow`, as `* /*`. `hosts` is
sorted. `scope` repeats the mode: `all` = every third-party host the gateway carries, `dynamic`
= only the hosts of the sources (for a wallet that replaces a compiled list, publish `all`).
`revision` is derived from `version`, `scope`, `max_age_secs` and `hosts`, so it changes
exactly when the document does and is the same on replicas with the same configuration and
the same hosts. The answer carries `cache-control: max-age` and
`etag: "<revision>"`; a request whose `if-none-match` names the current revision gets a 304
without a body. The request passes the same checks as any inner request (relay
authentication, freshness, replay) and counts as a READ; the gateway host's `BACKENDS_POLICY`
entry does not apply to it. A process that has no complete list answers an inner 503 instead
of a shorter list: until the document of every source has been read once since the start
(its hosts would be missing although other replicas serve them; a document without any valid
host counts as read, a source that cannot be fetched, parsed or verified does not, so the 503
lasts as long as such a failure; `ohttp_dynamic_hosts_last_success_timestamp_seconds` has no
value for that source), or if the document would exceed 256 KiB (logged
as an error once each time it becomes too large and counted in `ohttp_requests_total{status="unavailable",
backend="gateway"}`; wallets refuse a larger one). With `off` the path is an ordinary lightwalletd
path. What a wallet
does with the list: [README.md](README.md), "Third-party host list: wallet integration".

## Limits and timeouts

| Variable | Default | Meaning |
|---|---|---|
| `MAX_INFLIGHT_REQUESTS` | `1024` | OHTTP requests in flight per process, counted from after relay authentication and the content-type check until the response body ends. Above it: outer 503 with `Retry-After: 1`. Must be a positive integer. |
| `MAX_UPSTREAM_RESPONSE_BYTES` | `67108864` (64 MiB) | Largest upstream response body; a larger one is cut and answered with an error. Clients accept at most 256 MiB, so keep it at or below that. |
| `MAX_INFLIGHT_UPSTREAM` | `256` | Upstream calls in flight per process, all backends together. |
| `MAX_INFLIGHT_PER_BACKEND` | `64` | Upstream calls in flight per backend alias. |
| `MAX_INFLIGHT_LWD` | `128` | lightwalletd calls in flight per process. |
| `MAX_INFLIGHT_LWD_HEAVY` | `MAX_INFLIGHT_LWD / 4` (at least 1) | Of those, "heavy" calls at once: long `GetBlockRange`, `GetTransaction`, transparent-address and subtree queries. The rest stay free for `SendTransaction`, `GetLatestBlock`, `GetTreeState` and short ranges. |
| `LWD_HEAVY_BLOCK_RANGE` | `100` | `GetBlockRange` spans above this many blocks count as heavy. |
| `LWD_PERMIT_WAIT_MS` | `2000` | How long a lightwalletd call waits for a permit before it is refused with `UNAVAILABLE`; `0` refuses at once. A waiting call holds no permit. |
| `LWD_PERMIT_MAX_WAITERS` | `0` | Calls allowed to wait per class (heavy, general); beyond it they are refused at once. `0` means 4 times the permit count of each class. |
| `MAX_BLOCK_RANGE` | `10000` | Largest `GetBlockRange` span; larger spans get grpc-status 3. |
| `LWD_TIMEOUT_SECS` | `80` | Total time (head and body) for one upstream call, lightwalletd or third party. |
| `LWD_UNARY_TIMEOUT_SECS` | `10` | Total time of a lightwalletd RPC with one answer (`GetLatestBlock`, `GetTreeState`, `GetTransaction`, ...), at most `LWD_TIMEOUT_SECS`. A lightwalletd that accepts the connection but does not answer costs a call this long, so the client's retry can reach another instance. Not `SendTransaction` (next row). |
| `LWD_SEND_TIMEOUT_SECS` | `LWD_TIMEOUT_SECS` | Total time of a `SendTransaction` call, at most `LWD_TIMEOUT_SECS`. A broadcast cut by a deadline may still be sent by that lightwalletd while the client sees an error, so by default it keeps the overall timeout. Never retried once it reached lightwalletd. Counted as class `send` in `ohttp_lwd_timeouts_total`. A slow broadcast therefore holds its request up to `LWD_TIMEOUT_SECS` (default 80 s): the relay's and the clients' timeouts must be at least that, or set this lower. |
| `LWD_STREAM_IDLE_SECS` | `20` | For a server-streaming lightwalletd RPC (`GetBlockRange`, `GetSubtreeRoots`, ...): the longest wait for the response head and for each next frame. A stream that keeps sending runs up to `LWD_TIMEOUT_SECS`. `GetMempoolStream` keeps the long-poll settings below. The transparent-address RPCs (`GetTaddressBalance*`, `GetTaddressTxids`, `GetAddressUtxos*`) keep `LWD_TIMEOUT_SECS` for their first answer (the head and, for a stream, its first message), which waits for an address query of the node; their streams get this bound between frames after the first complete message. |
| `LWD_CONNECTION_POOL` | `false` | `1`/`true`/`on`: reuse pooled HTTP/2 connections to lightwalletd (idle 60 s, keep-alive PINGs every 20 s, closed when a PING is not answered within 5 s), saving a handshake per call. Three calls within 10 s that run into one of the deadlines above replace the pool (at most once per 5 s), so new calls open new connections; a single slow call does not. Default: a new connection per call, so a call never lands on a lightwalletd instance that has been taken out of service. |
| `LWD_CONNECT_TIMEOUT_MS` | `2000` | Longest wait for a connection to lightwalletd. A connection not established in time is a connect error, which every call retries once (no byte of the request was sent). An instance whose network is cut drops the connection attempt instead of refusing it; without this bound a call waited for its whole deadline. |
| `LWD_ENDPOINTS` | - | `host:port` of a name that resolves to one address per lightwalletd instance (for example a headless service of the instances behind `LWD_ADDR`). When set, the gateway resolves it every 5 s and sends each lightwalletd call to one of the addresses at random, skipping for 30 s an address whose last attempt failed while another one is left; the one retry (after a connect error, after an error that says the request was not written to its connection, and for a read after any transport error) and the hedge of a read go to another address. One resolution runs at a time; calls use the previous list meanwhile, and wait (at most 1 s, within their own deadline) only for the first one. `LWD_ADDR` stays the logical name (logs, the chain follower's key) and is used while the name has not resolved. Unset: every call goes to `LWD_ADDR`, a retry is a new connection to it, and reads are not hedged. |
| `LWD_HEDGE_DELAY_MS` | half of the head deadline | A read (every `CompactTxStreamer` RPC except `SendTransaction`) without a response head after this long is sent to a different `LWD_ENDPOINTS` instance as well; the first head wins, both within the call's whole head deadline. The other attempt is not cancelled (a cancelled call can cost the node behind lightwalletd an RPC slot): it runs to its end in a task of its own and its answer is discarded (`event="loser_detached"`; one whose request was not given to a connection yet is dropped, nothing of it was sent; its head still bounded by the call's head deadline, reading its body by 10 s and 8 MiB, `event="loser_expired"` when one of them cuts it). The loser is not counted as a failure, whatever it ends with; an instance that loses two hedges in a row, with no response head from it in between, is skipped for 30 s at that and each further loss (`event="loser_skipped"`). Not for heavy calls (long block ranges, transactions, transparent-address and subtree queries), `GetMempoolStream` and the transparent-address RPCs. Six hedges a minute are always allowed; above that, at most one hedge per ten hedgeable reads of the last minute (`event="rate_limited"` beyond), so hedging adds at most 10 % more lightwalletd calls plus at most 6 a minute. `0` turns hedging off. Metric `ohttp_lwd_hedges_total`. |
| `LWD_HEDGE_MAX_INFLIGHT` | `MAX_INFLIGHT_LWD / 8`, at most `16`, at least `1` | Hedges in flight per process at most (1 to the semaphore maximum); when all are in use a read is not hedged (`event="no_permit"`). A hedge is an upstream call on top of the caller's lightwalletd permit: hedges are not counted in `MAX_INFLIGHT_LWD`, so this bounds the extra concurrent calls. A permit is taken when a hedge is sent and held until the race ends (also while the first attempt still runs after the hedge failed); a read that is not hedged holds none. The same number bounds, apart from the hedges, the attempts that lost a race and run to their end detached: each holds a permit of a second set of this size (not a hedge permit, not one of `MAX_INFLIGHT_LWD`) until it ends; when all are in use the loser is cancelled as before (`event="loser_cancelled"`). So hedging adds at most twice this number of concurrent lightwalletd calls. |
| `LONG_POLL_MAX_INITIAL_SILENCE_SECS` | `25` | `GetMempoolStream`: the stream ends cleanly (grpc-status 0) if no message arrives within this time. Values above 25 are clamped to 25. |
| `LONG_POLL_IDLE_SECS` | `3` | `GetMempoolStream`: the stream ends cleanly after this much silence following a message. Clamped to 25. |
| `SSE_KEEPALIVE_SECS` | `20` | For a `text/event-stream` answer, a `: keep-alive` comment is sent after this much upstream silence. `0` falls back to 20; values above 25 are clamped to 25. |
| `MAX_CACHE_GET_CONCURRENCY` | `64` | Cache lookups in flight; beyond it a request bypasses the cache. |
| `MAX_LARGE_RESPONSE_CONCURRENCY` | `1` | Buffered upstream responses above `LARGE_RESPONSE_THRESHOLD` that may be held at once; when exhausted, the response still proceeds and a warning is logged. |
| `LARGE_RESPONSE_THRESHOLD` | `8388608` (8 MiB) | Size above which a buffered response counts as large. |
| `HEALTHZ_LWD_ERROR_RATIO` | `0.2` | `/healthz` answers 503 while, over the last `HEALTHZ_LWD_ERROR_WINDOW_SECS`, at least `HEALTHZ_LWD_MIN_ERRORS` lightwalletd calls failed and the failed ones are at least this share of all lightwalletd calls. A call failed when it got no response head after its retry (connect or transport error, deadline); errors that lightwalletd answers (a gRPC status) do not count, nor does a late head of `GetMempoolStream` (an empty mempool) or of a transparent-address RPC (a slow node query). This catches a lightwalletd that answers only some connections (one of several instances unreachable from this origin) while the chain follower's probe still passes. Between 0 and 1; `0` turns it off. Gauge `ohttp_healthz_lwd_error_ratio`. |
| `HEALTHZ_LWD_ERROR_WINDOW_SECS` | `30` | The window of `HEALTHZ_LWD_ERROR_RATIO`, 1 to 600 seconds. |
| `HEALTHZ_LWD_MIN_ERRORS` | `5` | Failed calls needed in the window before the ratio counts. |
| `REDIS_OP_TIMEOUT_MS` | `250` | Timeout of one cache or security Redis operation. |

The Encapsulated Request body is limited to 10 MiB (outer 413 above it) and must arrive within
30 s of the read starting (outer 400 otherwise). Neither is configurable.

## Responses

| Variable | Default | Meaning |
|---|---|---|
| `CHUNK_SIZE` | `16384` | Size of every non-final chunk of a chunked OHTTP response, in bytes; 1024 to 65536 (the client refuses response chunks above 64 KiB), anything else refuses to start. |
| `CHUNK_FLUSH_MS` | `50` | When upstream data stalls for this long, the bytes collected so far are sent as a short chunk. |
| `RESPONSE_PADDING` | `on` | `on`: the final chunk is zero-padded to `CHUNK_SIZE`, so response sizes are rounded up to whole chunks. `sensitive`: `GetLatestBlock`, `GetLightdInfo` and `SendTransaction` answers are left unpadded, every other answer is padded. `off`: no padding. |

## Replay protection and freshness

| Variable | Default | Meaning |
|---|---|---|
| `REDIS_SECURITY_URL` | unset | Redis (`redis://` or `rediss://`) for replay nonces and the cache epoch; must use `maxmemory-policy noeviction`. Its user (and the users of `REPLAY_PEER_URLS` / `REPLAY_STANDBY_URLS`) should be allowed `ROLE`: every new connection is accepted only on a node that says `ROLE master`; where the ACL refuses `ROLE` (`NOPERM`) connections are accepted without that check (a write on a replica still fails closed with `READONLY`). Required in `ohttp` mode together with `REDIS_URL`. While it is unreachable at startup the gateway retries every 5 s before listening. |
| `REPLAY_FRESHNESS` | `observe` | Inner `ohttp-freshness` timestamp check. `off`: ignored. `observe`: missing or stale timestamps are counted (`ohttp_freshness_total`) but served. `enforce`: refused with inner 400 carrying `ohttp-freshness: rejected`. |
| `REPLAY_FRESHNESS_WINDOW_SECS` | `300` | Accepted distance from the gateway clock, either direction. At most half the nonce TTL (600 s). |
| `REPLAY_WRITE_WAIT_REPLICAS` | `0` | When above 0, a WRITE request (anything not on `REPLAY_READ_ROUTES`) runs only after its nonce is acknowledged by this many replicas of the security Redis (`WAIT` on a dedicated connection); otherwise it is refused with inner 503 (grpc-status 14 for lightwalletd calls). For a replicated store with automatic failover. |
| `REPLAY_WAIT_CONNS` | `8` | Dedicated `WAIT` connections per store (the local security Redis for `REPLAY_WRITE_WAIT_REPLICAS`, each peer and standby store for `REPLAY_PEER_WAIT_REPLICAS`), 1 to 32; with `REPLAY_PEER_WAIT_REPLICAS=0` each peer and standby store has one connection for the `SET NX` retry instead. Used in two modes. **Shared** (normal): while that store's `WAIT`s return within their round trip plus half their timeout, many are in flight on each connection (round robin), which puts no cap on the WRITE rate. **Exclusive**: for 10 s after a `WAIT` of that store took longer, came back short or timed out (a resync), each connection serves one WRITE at a time, because `WAIT` blocks its connection and the `WAIT`s queued behind a slow one would run out of time. Then at most `REPLAY_WAIT_CONNS / (round trip + WAIT time)` WRITEs per second wait for that store's replicas, e.g. 8 / (0.1 s + 0.1 s) = 40 per second per pod for a store 100 ms away; a WRITE that finds every connection busy until less than its whole `WAIT` would still fit is treated as a short acknowledgement once a `SET XX` on the main connection found its nonce: the peer fallback may confirm it, otherwise it fails closed (`ohttp_replay_wait_saturated_total`). A connection stays with its WRITE until its `WAIT` is answered, also when the request gave up meanwhile, and a connection is leased only once no shared `WAIT` is left on it (nor used shared while leased). Only an open connection that reaches the primary is handed out: a WRITE waits for one to be released or opened until the last moment its whole `WAIT` still fits, then takes the saturated path if every open one was busy, or fails closed if none was open. A `WAIT` that gets no answer within its budget replaces that one connection; a second connection of the same store doing so within 5 s replaces all of them (only that counts as a change of the store for the WRITE fallback). A burst that arrives in shared mode at the very start of a resync queues on the connections before the switch, and the part of it that runs out of time counts as no answer (`REPLAY_UNAVAILABLE_FALLBACK` decides those). Housekeeping PINGs one idle connection per store and round; the last idle one (and the only one of a pool of one) is checked as shared work, so it is not PINGed while the pool hands out its connections exclusively. |
| `REPLAY_WRITE_WAIT_MS` | `100` | `WAIT` timeout for `REPLAY_WRITE_WAIT_REPLICAS`. After a failover of the store, WRITEs are admitted again once the promoted primary has this many replicas: with one replica in total, that is when the old primary has rejoined as a replica. With `REPLAY_PEER_URLS` and `REPLAY_PEER_WAIT_REPLICAS` >= 1, a WRITE whose nonce is new on the local primary but short of acknowledgements is confirmed at the peer stores instead (new there and acknowledged by their replicas; held there = replay; otherwise fail-closed) and written back locally later; see `docs/architecture.md`. Keep it below about 1.25 s: a housekeeping check of a `WAIT` connection gets that budget within its round, and a longer `WAIT` makes busy connections fail their checks. |

## Multiple origins

All of these are inert unless `REPLAY_PEER_URLS` is set (except `ORIGIN_ID`, which is a label
only, and `REPLAY_STANDBY_URLS`). See `docs/architecture.md`, "Multiple origins".

| Variable | Default | Meaning |
|---|---|---|
| `ORIGIN_ID` | `-` | Label of this origin, at most 32 characters of `[A-Za-z0-9._-]`. Log field `origin` and metric `ohttp_origin_info`; never sent to clients. |
| `REPLAY_PEER_URLS` | unset | The other origins' security Redis, comma-separated `redis://` / `rediss://` URLs, no duplicates. A nonce that any store already holds is a replay. |
| `REPLAY_PEER_TIMEOUT_MS` | `150` | Budget for the concurrent peer round trips of one request. |
| `REPLAY_PEER_FAIL_CLOSED` | `false` | `1`/`true`: a peer error or timeout refuses the request like a local security Redis failure. Default: the local verdict stands and the failure is counted; for a WRITE only if its route is on `REPLAY_ONE_SIDED_WRITE_ROUTES` (any other WRITE fails closed). |
| `REPLAY_PEER_MODE` | `sync` | `sync`: every nonce is written to every peer before the request runs. `async-reads`: READ requests are checked locally and their nonces replicated to the peers in the background; WRITEs stay synchronous. `failover`: every request is checked locally and every nonce replicated in the background (active/passive pair). |
| `REPLAY_PEER_FAIL_CLOSED_WRITES` | `true` | In `async-reads`: whether an unreachable peer refuses a WRITE. `0`/`false`: a WRITE on `REPLAY_ONE_SIDED_WRITE_ROUTES` runs on the local check alone while the peers are unreachable; the nonce is then replicated to those peers in the background once they are reachable again (until the nonce TTL). Any other WRITE still fails closed. |
| `REPLAY_STANDBY_URLS` | unset | The security Redis of each standby origin (one that runs WRITEs on its own store while the peers' store is unreachable), comma-separated `redis://` / `rediss://` URLs, none of them also in `REPLAY_PEER_URLS`. Every WRITE that passed the replay checks is also replicated there in the background (queue per store, retried until the nonce TTL). The hand-off never delays or refuses a request; with `REPLAY_PEER_WAIT_REPLICAS` >= 1 the stores also confirm `async-reads` WRITEs synchronously while the peers' store cannot acknowledge, and for one nonce TTL after startup or a disruption of it (a nonce held there is a replay; see `docs/architecture.md`). Set it on every origin whose WRITE check goes to a store the standby does not receive from (for example a read origin in `async-reads` checking WRITEs at the primary origin's store). |
| `REPLAY_READ_ROUTES` | every read-only lightwalletd RPC | READ allowlist for `async-reads`, in `BACKENDS_POLICY` syntax; the pseudo-authority `lwd` stands for the gateway's own lightwalletd. Anything not listed is a WRITE. The default lists no third-party route; a value replaces the default entirely, so include the `lwd=` entry. |
| `REPLAY_ONE_SIDED_WRITE_ROUTES` | empty | The WRITE routes that may run on the verdict of one replay store alone, in `REPLAY_READ_ROUTES` syntax (`lwd` = the gateway's own lightwalletd). Every other WRITE runs only once both the store that decides it (the local store in `sync` and `failover` mode, the hub in `async-reads`) and the second store it consults synchronously (the peers, the confirming standby stores, or the own store of an `async-reads` origin with `REPLAY_WRITE_WAIT_REPLICAS`) took its nonce as new; where one of them gives no verdict it fails closed (inner 503 / grpc-status 14, `ohttp_replay_write_fallback_total{result="one_sided_refused"}`) instead of running on the other's verdict (a peer tolerated by `REPLAY_PEER_FAIL_CLOSED[_WRITES]=0`, a fallback store that did not answer the check of every WRITE, `REPLAY_UNAVAILABLE_FALLBACK`). One network partition between two stores can run a listed route once at each side, so list only routes whose upstream refuses a second copy of the same request by itself, e.g. `lwd=POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction` (the chain never takes one transaction twice). A peer or standby `SET NX` that times out on such a both-stores path (and, with `REPLAY_PEER_FAIL_CLOSED=1`, on any `sync`-mode request) is retried once, at once, over another connection to that store (a `WAIT` connection; only with `REPLAY_PEER_WAIT_REPLICAS=0`, which opens no `WAIT` pool, one retry connection of its own per peer and standby store; `SET key value NX GET` with the request's own value, so a first write that landed is told from another request's): **this retry needs Redis >= 7.0 at the peer and standby stores; older stores answer it with an error and the WRITE fails closed as before.** **Upgrading:** a deployment that relies on WRITEs running while a peer, the hub or a standby store is unreachable must list those routes before it upgrades; the default refuses every such one-sided admission. **Exception:** a `failover`-mode origin without the peer fallback (no `REPLAY_WRITE_WAIT_REPLICAS`, or `REPLAY_PEER_WAIT_REPLICAS=0`) consults no second store on the request path: it decides every WRITE on its local store and only replicates the nonce afterwards, so this list does not apply there and a request sent to it and to a peer at the same time can run at both (an active/passive pair only; logged as a warning at startup). See `docs/architecture.md`. |
| `REPLAY_ASYNC_MAX_LAG_MS` | `500` | Background replication counts as degraded when its lag exceeds this; READs then use the synchronous path. |
| `REPLAY_ASYNC_RECOVERY_SECS` | `30` | How long replication must be healthy again before READs return to the background path. |
| `REPLAY_ASYNC_FAILURES_BEFORE_STRICT` | `3` | Consecutive peer failures that degrade background replication. |
| `REPLAY_PEER_WAIT_REPLICAS` | `1` | A WRITE nonce stored synchronously at a peer must reach this many replicas of that peer's store (`WAIT`) before the request runs; `0` turns it off (a peer store without replicas). On an `async-reads` origin the hub's `SET NX` and this `WAIT` go out together, one round trip, on one of the hub's `WAIT` connections (`REPLAY_WAIT_CONNS` >= 2) that no other request uses at that moment; otherwise `SET NX` on the main connection and then the `WAIT` as before. An error answer to that pipeline is resolved with `SET ... NX GET`, and a pipeline without a clear answer (none in time, or its connection broke) is asked again the same way on another connection, which needs Redis >= 7.0 at the hub. |
| `REPLAY_PEER_WAIT_MS` | `100` | `WAIT` timeout at the peer; a failed attempt is retried once. Both settings also apply to the standby stores (`REPLAY_STANDBY_URLS`) when the hub fallback confirms a WRITE there. Keep it below about 1.25 s: a housekeeping check of a `WAIT` connection gets that budget within its round, and a longer `WAIT` makes busy connections fail their checks. |
| `REPLAY_UNAVAILABLE_FALLBACK` | `false` | `1`/`true`: when the store that decides a request gives no verdict at all (unreachable, a timeout, an error), the request is decided at the fallback store instead of failing closed. `failover` mode (the local store is the deciding one): READs by `SET NX` at the peers, WRITEs by `SET NX` + the peers' `WAIT`. `async-reads` with `REPLAY_PEER_FAIL_CLOSED_WRITES` on (the hub is the deciding one): WRITEs confirmed at the standby stores (`SET NX` + `WAIT`), or by the local replicas when the origin has `REPLAY_WRITE_WAIT_REPLICAS`. `async-reads` without standby stores and with `REPLAY_WRITE_WAIT_REPLICAS` (the own store is the fallback store), whatever `REPLAY_PEER_FAIL_CLOSED_WRITES` says: when the own store gives no verdict, READs by `SET NX` at the hub and WRITEs by `SET NX` + the hub's `WAIT` (`ohttp_replay_local_fallback`). A nonce held there is a replay, anything else fails closed, and a WRITE nonce is written back to the deciding store (READ nonces are not: a replayed READ changes nothing). Only one store decides then, so a WRITE is decided this way only if its route is on `REPLAY_ONE_SIDED_WRITE_ROUTES`; any other WRITE fails closed (except after a local `SET NX` that took the nonce and a `WAIT` that got no answer, which counts like a short acknowledgement). Turn it on only once every origin that checks at the same stores reports `ohttp_replay_fallback_check` 1, i.e. runs a version that checks every WRITE at the fallback store and has the settings for it (`failover`: `REPLAY_WRITE_WAIT_REPLICAS` and `REPLAY_PEER_WAIT_REPLICAS` >= 1; `async-reads`: standby stores with `REPLAY_PEER_WAIT_REPLICAS` >= 1, or its own replica wait); see `docs/architecture.md`. Gauge `ohttp_replay_unavailable_fallback`. In `failover` mode, and on such an `async-reads` origin, it also changes `/healthz`: while the local store does not answer but every peer answered its last housekeeping PING (every 10 s), `/healthz` stays 200 (`ohttp_replay_serving_via_fallback` 1), so a load balancer keeps the origin; it fails when no store can decide. |
| `REPLAY_FALLBACK_HEALTH_FAILURES` | `20` | While the security Redis gives no verdict and the peer stores decide in its place (`REPLAY_UNAVAILABLE_FALLBACK`), `/healthz` stays 200 only as long as the WRITEs decided there do not keep failing: after this many in a row failed closed (`result` `unacknowledged`, `unavailable` or `overflow` on `path="local_unavailable"`: a peer short of replicas, a full write-back queue, a broken peer `WAIT` connection; and WRITEs refused because they are not on `REPLAY_ONE_SIDED_WRITE_ROUTES` while the own store gives no verdict), each within `REPLAY_FALLBACK_HEALTH_WINDOW_SECS` of the one before, it answers 503 (`ohttp_replay_fallback_writes_failing`) and stays so until the security Redis answers again or a WRITE decided through the fallback runs; it does not come back on a timer. Refusals caused by a peer that does not answer do not count. READs that still arrive are decided at the peers as before. `0`: off. |
| `REPLAY_FALLBACK_HEALTH_WINDOW_SECS` | `60` | See `REPLAY_FALLBACK_HEALTH_FAILURES`: failures further apart than this start a new count. |
| `REPLAY_STARTUP_STORES_WAIT_SECS` | `10` | At startup, `/healthz` and `/health/startup` (the readiness probe) answer 503 (`ohttp_replay_stores_pending` 1) until every replay peer and standby store is connected, with at least one open `WAIT` connection where its replica acknowledgement is required (`REPLAY_PEER_WAIT_REPLICAS`), and the local `WAIT` pool has a usable connection; at most this long, then the gateway reports ready anyway and warns. A WRITE that is not on `REPLAY_ONE_SIDED_WRITE_ROUTES` needs those stores, and a pod that took traffic before they connected would refuse it. `0`: do not wait. |
| `REPLAY_LOCAL_WAITAOF_MS` | auto (`2000`) | Only in `async-reads` with `REPLAY_PEER_FAIL_CLOSED_WRITES=0`: a WRITE whose nonce no peer took runs only after the local security Redis has fsynced it (`WAITAOF 1 0`). Unset: on if the store answers a `WAITAOF` probe at startup, off otherwise. `0`: off. A positive value: required (startup fails without AOF), with that timeout. |

### WRITE forwarding

A read origin can hand its WRITEs to a gateway next to the hub store instead of deciding them
across the long round trips to that store and calling the upstream from afar (see
`docs/architecture.md`, "WRITE forwarding"). Off unless both sides are configured; READs are
never forwarded.

| Variable | Default | Meaning |
|---|---|---|
| `REPLAY_WRITE_FORWARD_URL` | unset | Read origin (`REPLAY_PEER_MODE=async-reads` with `REPLAY_PEER_URLS`, and not `REPLAY_WRITE_WAIT_REPLICAS` > 0 without `REPLAY_STANDBY_URLS`, else a startup error): `http://host:port` of a gateway with `WRITE_FORWARD_BIND_ADDR` next to the hub store. Every WRITE whose nonce the local store took as new (or gave no verdict on) is posted there as the Encapsulated Request the relay sent (cleartext HTTP/2, pooled, PINGed every 2 s, closed after 5 s without an answer; for a private network only, without a proxy of its own in between: the request and the answer stay sealed to the client, the forwarding secret is in clear). That gateway handles it like a request from a relay, always as a WRITE (nonce, replay stores, replica wait, decryption, route policy, freshness, third-party rules, upstream), and its sealed answer is streamed back unchanged. This origin states what its own decision would require (header `ohttp-write-forward-requires`: `second-store` with confirming standby stores, `replica-ack=N` with `REPLAY_PEER_WAIT_REPLICAS` or its own `REPLAY_WRITE_WAIT_REPLICAS`, N the larger), and the receiving gateway declines what it cannot meet (`second-store`: its peers in `sync` mode or `ohttp_replay_fallback_check` 1; `replica-ack=N`: its own `REPLAY_WRITE_WAIT_REPLICAS` >= N). Run the receiving gateway with `REPLAY_UNAVAILABLE_FALLBACK` where the read origins have it: an error of its own store check fails the forwarded WRITE closed, where the read origin would have decided it at its fallback store. A `409` there is refused as a peer replay. Any other answer from it (a refused secret, busy, not every replay store connected there, a requirement it cannot meet, a request it cannot open) means it did not run the WRITE: it is decided here as without forwarding, as it is when no connection can be opened. A WRITE sent without an answer in time, or whose connection broke, or whose store there gave no verdict after the nonce may have been stored, fails closed (inner 503 / grpc-status 14). **Required, not checked:** the receiving gateway's own security store is the hub store this origin lists in `REPLAY_PEER_URLS`, its second store (peers or fallback store) is this origin's `REPLAY_STANDBY_URLS`, and both list the same `REPLAY_ONE_SIDED_WRITE_ROUTES`, fail-closed settings and route policy. Its second store must never be a forwarding origin's own store: an origin with its own replica wait and no standby stores (`REPLAY_WRITE_WAIT_REPLICAS` > 0 without `REPLAY_STANDBY_URLS`, a store other origins fall back to) is refused as a forwarder at startup. Unset: off. Needs `REDIS_SECURITY_URL`; refused together with `WRITE_FORWARD_BIND_ADDR`. The receiving gateway must use the hub store as its own security store (not this origin's), and the same `REPLAY_READ_ROUTES`, `REPLAY_ONE_SIDED_WRITE_ROUTES` and route policy. |
| `REPLAY_WRITE_FORWARD_SECRET` | unset | Required with `REPLAY_WRITE_FORWARD_URL`: the secret part of one `WRITE_FORWARD_SECRETS` entry of the receiving gateway (visible ASCII), sent as `X-Write-Forward-Secret`. |
| `REPLAY_WRITE_FORWARD_CONNECT_TIMEOUT_MS` | `1000` | Connection timeout of the forwarding client. A connection that cannot be opened: the WRITE is decided here. |
| `REPLAY_WRITE_FORWARD_TIMEOUT_SECS` | `90` | Until the head of the receiving gateway's answer, which comes once its upstream answered: keep it above that gateway's upstream timeouts (`LWD_SEND_TIMEOUT_SECS`, third-party timeouts). No answer by then fails closed. |
| `REPLAY_WRITE_FORWARD_BACKOFF_MS` | `5000` | After a WRITE the receiving gateway did not run for a lasting reason (no connection, the secret, not ready, a requirement), WRITEs are decided here at once for this long, without trying. An unclear answer of its store also starts it; a one-off decline (busy, a request it could not open) starts it only after three in a row. Clients cannot cause either: the read origin opens every request before it forwards it. |
| `WRITE_FORWARD_BIND_ADDR` | unset | Receiving gateway: `IP:port` of a listener of its own for forwarded WRITEs (`POST /ohttp-gateway/internal/v1/write` only, cleartext HTTP/2 only; never the public port, which does not answer that path). At most 256 connections, each must send the HTTP/2 preface within 10 s, idle ones are PINGed. Expose it to the read origins only. Needs `REDIS_SECURITY_URL`. It should check every WRITE at a second store (its peers in `sync` mode, or the check of every WRITE at a fallback store, `ohttp_replay_fallback_check` 1) and have its own replica wait (`REPLAY_WRITE_WAIT_REPLICAS`): otherwise it declines the WRITEs of read origins that require them (logged at startup). A forwarded request is opened before its replay check, so one it cannot open (keys that differ from the read origin's) costs no nonce. |
| `WRITE_FORWARD_SECRETS` | unset | Required with `WRITE_FORWARD_BIND_ADDR`: accepted forwarding secrets, `RELAY_SECRETS` syntax (`name=secret`, comma-separated); the name is the `relay` label and log field of the forwarded requests, so give all read origins one name unless telling them apart there is wanted. A missing, duplicated or unknown secret gets 401 (the read origin then decides the WRITE). |

## Caches

| Variable | Default | Meaning |
|---|---|---|
| `REDIS_URL` | unset | Cache Redis (`redis://` or `rediss://`), an evicting policy such as `allkeys-lfu`. Required in `ohttp` mode. |
| `LOCAL_CACHE_BYTES` | `268435456` (256 MiB) | In-process LRU in front of the cache Redis for blocks and tree states; `0` disables it. |
| `LOCAL_CACHE_MAX_ENTRY_BYTES` | `65536` | Values larger than this are not admitted to the in-process LRU. |
| `PERMANENT_REDIS_URL` | unset | Disk-backed store speaking the Redis protocol, without eviction, for final blocks (100 or more below the tip). Unreachable at startup: disabled until the next restart. |
| `PERMANENT_MIN_HEIGHT` | Sapling activation of `NETWORK` | Lowest height kept in the permanent tier. |
| `PERMANENT_OP_TIMEOUT_MS` | `2000` (serving), `5000` (`backfill`) | Timeout of one permanent-tier operation. |
| `CHAIN_TIP_STALE_SECS` | `150` | A stored chain tip unmoved for longer (by its `tip_at`, and by how long a process has read the same stored record on its own clock) makes the chain follower's other processes compare it with their own lightwalletd: one that is ahead serves its own tip (for at most 30 s after its lightwalletd last answered with it) and, still ahead on the next check with the same stored tip and lock holder, takes the leader lock over. |
| `PREFETCH_TIP` | `1` | On every new tip, the chain follower's leader fetches `GetLightdInfo` and `GetLatestTreeState` once and caches them under the tip, and writes the tip's `GetSubtreeRoots` end markers from the tip block's commitment tree sizes, so the first requests after a block are cache hits. `0` turns it off. |
| `PREFETCH_BLOCK_TXS` | `0` | `1`: the leader also fetches every transaction of each new block with `GetTransaction` and caches it (validated like a Client's answer), so wallets syncing to the tip find recent transactions cached. Costs one upstream call per transaction. |
| `PREFETCH_BLOCK_TXS_MAX` | `100` | With `PREFETCH_BLOCK_TXS=1`: blocks with more transactions than this are skipped. |
| `PREFETCH_TREE_STATE` | `0` | `1`: the leader also fetches `GetTreeState` of each new tip height (and of tips it skipped, at most 10) and caches it as the validated answer of a Client's height-only request. Wallets ask for the tree state at the height they last synced to; those heights are not final yet, so the pinned tier never has them. Costs one upstream call per block. |
| `REDIS_PINNED_URL` | unset | Optional Redis (no eviction) for `GetTreeState` answers by height. Needs `PINNED_TREESTATE_RANGE`. Only heights deeper than 100 blocks below a fresh tip are looked up there (only those are written). May be a read replica: the gateway asks its `ROLE` at startup and then writes nothing to it (and asks again every 5 minutes, and after a `READONLY` answer). |
| `REDIS_PINNED_WRITE_URL` | unset | Where pinned entries are written instead of `REDIS_PINNED_URL`, for a `REDIS_PINNED_URL` that is a read replica: normally its primary, so that a height the replica misses is written once for every gateway reading a replica of it. Writes are off the request path; their timeout is at least 2 s. Unreachable at startup: entries are written to `REDIS_PINNED_URL` (nothing when that is a replica) while the gateway keeps trying to connect it in the background (backoff 1 s up to 60 s); once connected, its `ROLE` is asked and it is used without a restart. A store whose `ROLE` does not answer in time is not written to and asked again after 30 s. |
| `PINNED_TREESTATE_RANGE` | unset | Inclusive height range for the pinned tier, `start-end` or `start-` (open end); `start` at least 1. Lookups use the whole range. The backfill workers and the sweep (`PINNED_BACKFILL_WORKERS`) fill it from the network's Sapling activation at the earliest (419200 for `NETWORK=mainnet`; 280000 for `testnet` and any other label): there is no tree state below it, so a range that starts lower costs nothing there, and one that ends below it is never backfilled. Sweep holes below that height, and below the range start after the range was raised, are dropped. |
| `PINNED_BACKFILL_WORKERS` | `0` | Background workers per process that fill the pinned range; `0`: write-through only. They share a cursor in the store; about every 10 minutes a sweep also checks the heights the cursor passed (from a shared mark on, one process per batch of 500) and fills any that are missing, such as a height whose claim was lost to a timeout (`ohttp_cache_requests_total{rpc="GetTreeState",result="pinned_sweep"}`); one it cannot fill is kept and retried by later sweeps (`result="pinned_sweep_failed"` per failed fill; dropped after 10 retries on which the upstream answered, `pinned_sweep_dropped`). Heights below the Sapling activation are skipped by the workers (the cursor moves past them in one step; a step the store refuses is logged at most once a minute and tried again before the next claim, the workers skipping those heights one by one meanwhile) and by the sweep; holes recorded there by an earlier version, and holes below the range start after the range was raised, are dropped without an upstream call, also as `pinned_sweep_dropped` (counted, with one log line of their number at most once a minute, once the store has removed them). When the store the entries go to changes during a fill, the fill is abandoned and counted: `pinned_backfill_superseded` for the height a worker had claimed, `pinned_sweep_superseded` for a sweep fill (within a second plus the bound of one claim command, four store timeouts and at least 2 s on a separate write store, of the change; its claim of the batch is then released by one more such command, checked by its token). An abandoned sweep fill (changed store, lost claim, fill timeout) does not cancel its upstream call in flight: the call runs to its end, its answer unused (`pinned_fetch_detached`); at most 3 sweep-started upstream calls per cache are alive at a time, awaited or abandoned; a sweep fill waits for one, within its fill timeout, only while all three are. While the store the entries go to does not take writes (a read replica, or no `ROLE` answer), the workers wait and the sweep skips its passes; they start once it does (a promoted replica, a write store that became reachable). All of them use the same store and choose again when it changes or a cursor command fails. |

## `zodl-ohttp-gateway backfill`

The `backfill` subcommand fills the permanent tier from lightwalletd and exits. It reads
`NETWORK`, `LWD_ADDR`, `LWD_TIMEOUT_SECS`, `MAX_INFLIGHT_LWD`, `PERMANENT_REDIS_URL` (required),
`PERMANENT_OP_TIMEOUT_MS`, `PERMANENT_MIN_HEIGHT` and the variables below (a malformed
`BACKFILL_*` number falls back to its default):

| Variable | Default | Meaning |
|---|---|---|
| `BACKFILL_START` | `PERMANENT_MIN_HEIGHT` | First height. |
| `BACKFILL_END` | tip - 100 | Last height; capped at tip - 100. |
| `BACKFILL_BATCH` | `500` | Heights per batch. |
| `BACKFILL_CONCURRENCY` | `2` | Batches in flight. |
| `BACKFILL_PAUSE_MS` | `200` | Pause after every run fetched and written. |
| `BACKFILL_POOL` | empty | Pool filter variant to fill; the empty filter is what wallets request. |

The run is resumable: present heights are skipped and a checkpoint is kept in the store.
