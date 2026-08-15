---
title: "Security"
permalink: /docs/security/
toc: true
---

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

The SOCKS proxy additionally rejects requests carrying a bare IP literal by default, so a client
configured with `socks5://` instead of `socks5h://` fails loudly rather than leaking quietly.

### Redirects cannot replay your credentials

`Authorization`, `Proxy-Authorization` and `Cookie` are stripped whenever a redirect crosses an
origin boundary. Without this, any server you talk to could bounce you to a host of its choosing and
harvest your bearer token.

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

A few kilobytes of gzip can expand to gigabytes. The response limit is enforced against the
*decompressed* output while it streams, and again against the declared `Content-Length` before any
body is read at all. Stacked encodings such as `gzip, br` are refused rather than half-decoded.

### Static file serving is confined

Request paths are rejected before touching the filesystem if they contain any traversal component,
then canonicalised and confirmed to resolve inside the configured root. Canonicalisation resolves
symlinks, so a link inside the directory pointing outside it is caught too.

### Response headers cannot be split

Header values containing CR or LF are refused rather than written to the socket. Otherwise a handler
that echoes user input into a header could inject headers, or an entire second response.

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

See [Onion services]({{ site.baseurl }}/docs/server/#hardening) for how to configure each.

### Your state directory is key material

The `.onion` address is derived from a keypair arti stores in `state_dir`. Anyone who copies that
directory can impersonate your service, and there is no revocation mechanism. Back it up as you
would a TLS private key, and no more widely.

### Client authorisation keys

hypertor accepts client public keys but will not generate keypairs for you. The secret half belongs
on the client and must never exist on the server; an API that returned both would invite exactly
that mistake. Clients generate their own with `arti hsc get-key`.

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

hypertor 0.3 tracks **arti 0.45**.

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
