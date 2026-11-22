# Relay weights

An application ships with a fixed, ordered list of relays for each network, and every request goes
to one of them, chosen at random. Without anything else each relay gets an equal share. The gateway
operator may publish a small signed block that changes the shares, for example to move traffic away
from a slow relay or to bring in a new relay gradually. The block can do nothing else: it names no
relay, it holds one integer per position of the application's own list together with a fingerprint
of that list, and a client whose list differs in any way ignores it.

## Where the block travels

The block is the value of the top-level field `relay_weights` of the signed key-configuration
envelope (`GET /ohttp-configs/signed`), which every client already fetches through a relay, or
from DNS as the base64 of the same bytes. It adds no request and no identifier. The envelope's own
signature does not cover it: the block carries a signature of its own, under a key of its own. So
whoever carries the envelope (the gateway, a relay, the DNS path) can withhold the block or swap in
an older one that is still valid, but cannot make or change one. A withheld or older block leaves
a client on what it holds (below), so the worst a carrier can do is delay a change, for at most the
validity of the older block; the client fetches the envelope through the relays of weight 0 last.

Clients that do not know the block ignore the field (unknown envelope fields are ignored). The field
appears at most once: under the reference policies (any repeated top-level key refused) an envelope
with it repeated is refused, as for any repeated field. An explicit `null` is no block. A DNS
publisher must publish the envelope's bytes as served, not a re-serialization of them.

## Format

```json
{"v":1,"network":"testnet","seq":1767225600,"not_before":1767225300,"not_after":1769817300,
 "n":2,"set":"377f979ac611fd84","weights":[70,30],"key_id":"6c8f8607","sig":"<base64>"}
```

| Field | Meaning |
|---|---|
| `v` | 1 |
| `network` | `mainnet` or `testnet` |
| `seq` | the signing time, Unix seconds; a client takes no block with a lower `seq` than the one it holds, and none with a `seq` more than 60 s ahead of its clock |
| `not_before`, `not_after` | validity, Unix seconds; `not_before < not_after`, at most 30 days apart |
| `n` | the number of relays of the list, 1 to 8 |
| `set` | the fingerprint of the list, 16 lower-case hex digits (below) |
| `weights` | `n` JSON integers, each 0 to 100, adding up to 100, in list order |
| `key_id` | the first 4 bytes of SHA-256 of the signing key, hex; informational only |
| `sig` | the Ed25519 signature (RFC 8032, pure), 64 bytes, standard base64 with padding |

Exactly these ten fields, each once. The block is at most 4096 bytes.

### `set`

`set` = the first 8 bytes of SHA-256 over each relay URL of the list in its canonical form, each
followed by one line feed (`0x0a`), in list order, as lower-case hex. The canonical form is the one
the client keeps a relay URL in (`canonical_relay_url`): `https://`, the host in lower case (an IPv4
address in dotted decimal, an IPv6 literal bracketed in its standard form), `:port` only when it is
not 443, the path with dot segments resolved, percent-encoding normalized and one trailing `/`
removed. `https://Relay-A.Example:443/relay/` is `https://relay-a.example/relay`.

### Signed message

```
"zodl-ohttp-relay-weights-v1" || 0x00 || network || 0x00 || u64be(seq) || u64be(not_before)
  || u64be(not_after) || u8(n) || set (8 bytes) || u8(weight 1) || ... || u8(weight n)
```

The block id is the SHA-256 of the signed message, 64 lower-case hex digits; it identifies the
block in a log and on a client's diagnostics screen whatever JSON spelling carries it.

## Client rules

A client with a relay weights key configured checks the block after the envelope checks out, and
ignores it (the block it holds, if any, stays in force; otherwise the shares are equal) when any
of these holds:

- it is too large, not a JSON object of exactly the fields above, or a field has another type;
- `v` is not 1, or `network` is not the network of the envelope;
- `n` or the number of weights is not the number of configured relays, or `set` is not the
  configured list's fingerprint;
- a weight is over 100, or the weights do not add up to 100;
- the validity is over 30 days, or the block is not valid now (60 s of clock skew on both ends);
- `seq` is more than 60 s ahead of the clock;
- the signature does not verify under the configured key;
- `seq` is lower than that of the block it holds, or equal to it with another block id.

An ignored block never makes the envelope fail, and never replaces the block the client holds: an
envelope without a block, or with one that is ignored, leaves the held block in force until it
expires. A valid block is held in memory only and applies to every relay choice while it is valid,
checked at each use: once it expires the shares are equal again, even with the envelope still
cached. A relay of weight 0 is never drawn for a request, but
requests still fail over to it; no request goes to a relay outside the configured list. Without a
configured key the block is never read.

## Test vectors

- `relay-weights-test-vector.json`: the key (seed, public key, key id), a relay list as written and
  in canonical form, its `set`, the fields, the signed message, the signature, the block as JSON and
  the block id; and `negative`: blocks a client must ignore, each with the time to check it at and
  the check that refuses it (wrong `set`, bounds, types such as `7e1` or `100.0`, repeated fields
  also under an escaped name, unknown field, `seq` ahead, expiry, validity, domain, signature).
- `relay-url-vectors.json`: relay URLs and their canonical form (case, default port, trailing
  slash, dot segments, percent-encoding, IDNA punycode, IPv4 and IPv6 literals), URLs that are
  refused, and relay lists with their `set`. An implementation that computes `set` itself must
  give these values.

## Operating it

- **Propagation.** A client reads a new block when it next fetches the envelope: when the cached
  envelope expires (its `not_after`) or the gateway refuses its key. Expect up to the envelope's
  validity. Outages are handled by the per-request failover, not by a block.
- **Revocation.** Only a block with a higher `seq` replaces a held one. Removing the block from the
  gateway revokes nothing: clients that hold it keep it until it expires (new processes start with
  equal shares). To undo a change, sign weights as equal as integers adding up to 100 allow (with
  3 relays, 34/33/33: within one point of the default 1/n), or delete the block and let it lapse.
- **Rollback protection is per process.** Nothing is persisted, so after a restart a client takes
  any valid block, also an older one; keep validity short enough for that to be acceptable.
- **Clock.** A client refuses a `seq` more than 60 s ahead of its clock; serve a block a little after
  its `seq`.
