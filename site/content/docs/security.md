+++
title = "Security"
description = "hypertor's threat model: what the design protects against, what it deliberately does not, and why."
weight = 7
+++

## What hypertor is, and is not

hypertor is a layer over [arti](https://gitlab.torproject.org/tpo/core/arti) and
[hyper](https://hyper.rs). All Tor cryptography, path selection and protocol handling is arti's; all
HTTP framing is hyper's. hypertor supplies the seam and the ergonomics.

That is deliberate. A library that reimplemented any of this would be strictly worse than the
projects that specialise in it — and in a privacy tool, "worse" means "gets someone hurt".

**hypertor is not an anonymity system in its own right, and no library can be.** Tor protects the
network path. It cannot protect you from an application that logs in with your real identity, from
timing patterns in your own traffic, from a browser fingerprint, from a document that phones home,
or from a compromised machine.

## Design choices that protect you

### DNS is never resolved locally

Hostnames are always handed to arti and resolved by an exit relay. A Tor integration that resolves
locally emits a plaintext DNS query from your real IP for every host you visit — the traffic is
tunnelled but the browsing history is not. This is the most common way a Tor integration leaks.

The SOCKS proxy attacks this from both sides. It rejects requests carrying a bare IP literal by
default, so a client configured with `socks5://` instead of `socks5h://` fails loudly rather than
leaking quietly. And it implements Tor's `RESOLVE` and `RESOLVE_PTR` SOCKS extensions, so a client
that wants a name looked up can ask the proxy to do it — without them such a client either fails or
falls back to the system resolver, which is the very leak the proxy exists to prevent.

### Onion addresses are checked before a circuit is built

A `.onion` name that is not 56 characters of base32 cannot resolve, so hypertor refuses it at the
call site rather than spending a circuit discovering that. Version 2 addresses — 16 characters,
1024-bit RSA and SHA-1, retired from the network in 2021 — are named explicitly in the error, since
someone holding one has stale information rather than a broken configuration.

### Redirects cannot replay your credentials

`Authorization`, `Proxy-Authorization` and `Cookie` are stripped whenever a redirect crosses an
origin boundary. Without this, any server you talk to could bounce you to a host of its choosing and
harvest your bearer token.

### Redirect targets are normalised before they are used

A `Location:` of `../elsewhere` is resolved against the base URL and its `.` and `..` segments are
removed, per RFC 3986 §5.2.4, before the follow-up request is built. Passing `/a/b/../c` on to the
server verbatim would leave hypertor and the server able to disagree about which resource was
requested — the shape of every path-confusion bug — and would make hypertor's own same-origin
reasoning run on a path nobody else sees.

### There is no cookie jar

Deliberately. A jar shared across requests would relink activities that circuit isolation exists to
keep apart: the separation would still be real at the network layer while the application layer gave
the correlation away for free. Set `Cookie` yourself when you want one, and its scope is yours to
choose. hypertor strips it on any cross-origin redirect, as it does the other credential headers.

### Redirects to schemes Tor cannot carry are refused

A `Location:` naming `mailto:`, `javascript:` or `file:` is refused with a message that says so,
rather than being handed down to the connector where it would surface as a confusing URL-parsing
error several layers from its cause.

### Onion-to-clearnet redirects are refused

A connection to a `.onion` never leaves the Tor network and is authenticated by the address itself.
Following a redirect out to clearnet moves the next request onto a path through an exit relay — an
untrusted party by design, which sees the destination and, absent TLS, the content.

hypertor refuses that transition unless you opt in with
`RedirectPolicy::allow_onion_to_clearnet(true)`. The reverse direction, clearnet to `.onion`, is
always allowed: that is an upgrade.

### Hostnames are scrubbed from errors

Error messages end up in logs, crash reports and issue trackers. `connection to
secretforum.onion:80 failed` is a leak. Every host in an `Error` is wrapped in
[`safelog::Sensitive`](https://docs.rs/safelog) and renders as `[scrubbed]` unless the application
explicitly opts in. `Error::host()` returns the real value when you need it programmatically.

### Size limits apply to decompressed bodies

A few kilobytes of gzip can expand to gigabytes. hypertor never decompresses a buffer and then
checks its size: the body is decoded incrementally and abandoned the moment the *decoded* output
crosses the limit, so a decompression bomb costs the limit and not a byte more. A declared
`Content-Length` over the limit is refused before any body is read at all, and stacked encodings
such as `gzip, br` are refused rather than half-decoded.

That early refusal is skipped where the metadata does not describe real bytes — the answer to a
`HEAD`, and any `204` or `304` — because there the declared length belongs to a body that is not
being sent.

The stacked-encoding check spans **every line** of the `Content-Encoding` field, not just the first.
RFC 9110 §5.2 makes repeated field lines equivalent to one comma-joined line, and `HeaderMap` keeps
them separate rather than joining them — so a server answering with

```text
Content-Encoding: gzip
Content-Encoding: br
```

used to be read as plain `gzip`. The body was gunzipped and handed back still Brotli-compressed:
exactly the outcome the refusal exists to prevent, reachable by any server that spells the field
over two lines. `If-None-Match` is read the same way, for the same reason.

The same machinery serves both the buffered and the streaming response APIs, so `send_streaming` is
not a way around the limit — there is exactly one place this can be got wrong.

### Streamed request bodies are never silently replayed

A body read from a file or a stream cannot be rewound. hypertor therefore refuses to retry such a
request, and refuses to replay it across a `307` redirect, rather than sending a truncated request
that the server would accept as complete.

### Onion services are not distinguishable

A hosted service accepts only `BEGIN` streams, and only for the virtual ports it publishes;
everything else is rejected with `END DONE`. arti's own documentation warns that an implementation
which behaves differently *"will be distinguishable"*, and a service that stands out from every
other service on the network has lost something no amount of encryption returns.

The HTTP layer bounds what a client can hold open: a deadline for sending request headers
(`header_timeout`), a cap on the request body (`max_body_size`), and a cap on concurrent connections
(`max_connections`). A slowloris is cheaper to mount against an onion service than against a
clearnet host, because the attacker's address is hidden by the same network that hides yours.

### Static file serving is confined

Request paths are rejected before touching the filesystem if they contain any traversal component,
then canonicalised and confirmed to resolve inside the configured root. Canonicalisation resolves
symlinks, so a link inside the directory pointing outside it is caught too.

A directory request serves its `index.html` or nothing. Directory listings are never generated:
publishing filenames the operator did not choose to expose is a leak dressed up as a convenience.

Files are streamed off disk rather than read into memory. Buffering them would let a handful of
concurrent requests for one large file exhaust the service's memory — and here the requester's
address is hidden by the same network that hides the operator's.

### An onion service publishes no timestamp

`Date` is **not sent** by default. A timestamp on every response is an oracle
for Murdoch's clock-skew attack ([CCS 2006](https://murdoch.is/papers/ccs06hotornot.pdf)):
quartz crystals change speed with temperature, so an attacker loads the hidden
service to warm it, then asks candidate machines for timestamps until one shows
the matching drift. A service that answers no timestamp does not play.

The counter-argument is hypertor's own — behaving differently is itself a
fingerprint, and nginx and Apache both send `Date`. It is weighed differently
here. At the Tor protocol layer there is one normal behaviour to blend into,
which is why a service answers only `BEGIN`; at the HTTP layer onion services
are already wildly heterogeneous, so the blending buys little while the clock
oracle costs a lot. `OnionApp::date_header(true)` restores it if you need
RFC-conformant caching more than you need this.

### Static file validators cannot be reproduced off-host

OnionScan's survey of the dark web found `ETag`, `Last-Modified`, `Server` and
`X-Powered-By` among the headers most useful for **matching a hidden service to
the ordinary host serving the same files**.

hypertor sends no `Server`, no `X-Powered-By` and no `Last-Modified` at all. The
`ETag` on a static file is a keyed hash of the file's size and modification
time, under a key generated when the process starts — so it still changes
exactly when the file changes, but it cannot be recomputed by anyone holding a
copy of the file, and two services serving identical content publish unrelated
validators. It also embeds no timestamp, for the reason above.

The cost is that validators change across restarts, so caches revalidate once.

### Static files are not sniffed

Every static response carries `X-Content-Type-Options: nosniff`. The content
type is guessed from the file extension, and a browser second-guessing that
guess is how an uploaded `.txt` becomes script.

### Response headers cannot be split

Header values containing CR or LF are refused rather than written to the socket. Otherwise a handler
that echoes user input into a header could inject headers, or an entire second response.

## TLS

### Post-quantum key exchange

The crypto provider is **aws-lc-rs**, whose defaults lead with the `X25519MLKEM768` hybrid key
exchange: classical X25519 combined with ML-KEM-768, so a session key is safe unless *both* are
broken.

That matters more here than in most places. "Harvest now, decrypt later" — record traffic today,
decrypt it once a cryptographically relevant quantum computer exists — describes an adversary with
exactly the resources and the patience to be interested in people who route their traffic over Tor.

hypertor previously forced the `ring` provider, which implements no post-quantum group at all, and
did so while `aws-lc-rs` was *also* being compiled in for arti. That combination cost a second
crypto library, forced an explicit provider install to stop rustls panicking over the ambiguity, and
silently gave up post-quantum key exchange. Now there is one provider, it is the one arti already
uses for Tor link TLS, and the whole process speaks a single cryptographic stack.

### Session resumption cannot cross an isolation boundary

rustls enables TLS session resumption by default, and a shared resumption store quietly undoes
circuit isolation: two requests placed on deliberately different circuits would still present the
**same session ticket** to the server, which can then link them however carefully the network layer
kept them apart. This is the same cross-site tracking vector browsers partition their TLS session
caches to prevent.

hypertor gives every isolation group its own session store, and `IsolationLevel::PerRequest`
disables resumption outright — a connection used once can never benefit from a ticket, and storing
one only creates something for a later connection to be correlated by. The isolation group *is* the
boundary within which linkage is something you already accepted.

`ConfigBuilder::tls_session_resumption(false)` turns it off entirely, at the cost of a full
handshake on every connection.

### 0-RTT and key logging are off

TLS 1.3 early data is never enabled: 0-RTT payloads are replayable by anyone who observes them.
rustls only writes `SSLKEYLOGFILE` when asked to, and hypertor never asks.

## TLS fingerprinting

`rustls` is the default backend, and it should stay that way.

TLS handshakes are fingerprintable: the set and ordering of cipher suites, extensions, supported
groups and signature algorithms differ per implementation. `native-tls` binds to whatever the host
provides — OpenSSL on Linux, SecureTransport on macOS, SChannel on Windows — so your ClientHello
announces your operating system to the exit relay and anyone watching it. That shrinks your
anonymity set for no benefit.

With `rustls`, every hypertor user emits the same ClientHello regardless of platform.

`native-tls` also cannot enforce a TLS 1.3 floor or negotiate ALPN. hypertor returns an error for
`min_tls_version(Tls13)` on that backend rather than silently giving you TLS 1.2 — a downgrade you
did not agree to is worse than a failure you can see.

### TLS is not applied to `.onion`

Onion connections are already end-to-end encrypted and authenticated by the rendezvous protocol, and
the address *is* the service's public key. hypertor only wraps a `.onion` target in TLS if the URL
says `https://` explicitly.

## Circuit isolation

Two requests sharing a circuit exit Tor from the same relay at the same moment and are linkable by
anyone observing it. hypertor defaults to `IsolationLevel::PerHost`, so different destinations never
share a circuit.

For activities that must not be linked *within* one host — separate accounts, separate personas —
use explicit tokens:

```rust
let alice = IsolationToken::new();
let bob = IsolationToken::new();
```

Each isolation group gets its own connection pool, so an isolated request can never be handed a
connection belonging to another group.

`IsolationLevel::PerRequest` is the strongest and the slowest: connection reuse becomes impossible
by construction, so every request pays a full circuit build.

## Onion service hardening

| Threat | Defence | arti API |
|---|---|---|
| Guard discovery | Vanguards | `VanguardConfigBuilder::mode` |
| Introduction floods | Proof of work (Equi-X), `pow` feature | `enable_pow` |
| Introduction floods | Token-bucket rate limit | `rate_limit_at_intro` |
| Stream flooding | Per-circuit stream cap | `max_concurrent_streams_per_circuit` |
| Unauthorised discovery | Restricted discovery | `RestrictedDiscoveryConfigBuilder` |
| Censorship of Tor itself | Bridges and pluggable transports | `TorClientConfigBuilder::bridges` |

See [Onion services](@/docs/server.md#hardening) for how to configure each.

### Your state directory is key material

The `.onion` address is derived from a keypair arti files under the service **nickname** inside its
state directory. Anyone who copies that directory can impersonate your service, and there is no
revocation mechanism. Back it up as you would a TLS private key, and no more widely.

Note that the default state directory is a persistent per-user one, so a service is **not**
ephemeral just because you did not set `state_dir` — relaunching with the same nickname republishes
the same address. If you meant the service to be short-lived, give it a nickname or a directory that
is not reused.

### Client authorisation keys

hypertor accepts client public keys but will not generate keypairs for you. The secret half belongs
on the client and must never exist on the server; an API that returned both would invite exactly
that mistake. Clients generate their own with `arti hsc get-key`.

**Connecting to a restricted-discovery service works with no extra code.** arti keeps a keystore in
the client's state directory and consults it automatically when it meets an onion address, so a
client that has been given a key reaches the service through the ordinary `client.get(...)`. Install
the key with `arti hsc get-key --onion-name <address>.onion`, pointed at the same state directory
the client uses — see [Client](@/docs/client.md#reaching-a-restricted-service).

## What hypertor does *not* disguise

hypertor sends [Tor Browser's User-Agent](@/docs/client.md) and matches its
`Accept-Encoding` ordering, so it is not singled out by those fields. It is worth being blunt about
how far that goes, because a false sense of protection is worse than none.

A server that looks past the User-Agent can tell hypertor from a browser immediately: there is no
`Accept` or `Accept-Language`, no `Sec-Fetch-*`, no request for any subresource, no JavaScript, and
the TLS ClientHello is rustls's rather than NSS's. Header order differs too.

hypertor does not try to close that gap. Faking a browser convincingly is a whole-application
problem — Tor Browser solves it by controlling the entire stack — and a library that half-solved it
would invite reliance on something that does not hold. What the default *does* achieve is that
hypertor volunteers no identifier of its own. If you are calling an API rather than pretending to
browse, an honest User-Agent for your application is a perfectly reasonable choice.

## Censorship circumvention

Where Tor's published relay addresses are blocked, connect through a bridge:

```rust
TorClient::builder()
    .bridge("obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0")
    .transport("obfs4", "/usr/bin/lyrebird")
    .build()
    .await?;
```

Get bridge lines from [bridges.torproject.org](https://bridges.torproject.org). Published, shared
bridges are the first ones a censor blocks; request your own.

A bridge line naming a transport is useless without the binary that speaks it, so hypertor rejects
that combination at build time rather than hanging until timeout with no indication of why.

## Keeping arti current

The Tor network retires obsolete protocol versions. An outdated client is both conspicuous — a
smaller, more identifiable population — and eventually non-functional. Update hypertor when it
tracks a new arti release.

hypertor 0.4 tracks **arti 0.45**.

## Reporting a vulnerability

Open a [security advisory](https://github.com/hupe1980/hypertor/security/advisories/new) rather than
a public issue.

For vulnerabilities in Tor itself or in arti, report to the
[Tor Project](https://gitlab.torproject.org/tpo/core/arti/-/issues) — hypertor is not the right
place, and delay costs users.

## Further reading

- [Tor Project support](https://support.torproject.org/)
- [Tor specifications](https://spec.torproject.org/)
- [arti documentation](https://tpo.pages.torproject.net/core/arti/)
- [Proof-of-work defence for onion services](https://blog.torproject.org/introducing-proof-of-work-defense-for-onion-services/)
- [Vanguards specification](https://spec.torproject.org/vanguards-spec/)
