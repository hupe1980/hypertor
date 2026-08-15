+++
title = "Documentation"
description = "Guides for the hypertor Tor HTTP client, onion service framework, SOCKS5 proxy and Python bindings."
sort_by = "weight"
template = "section.html"
page_template = "page.html"
insert_anchor_links = "heading"
+++

hypertor makes HTTP requests over the Tor network and hosts onion services, from Rust or Python.
It is a thin layer over [arti](https://gitlab.torproject.org/tpo/core/arti) and
[hyper](https://hyper.rs), supplying the seam between them and the ergonomics on top.

New here? [Installation](@/docs/installation.md) covers feature flags and TLS backends;
[Quick start](@/docs/quickstart.md) gets a request out. If you care about *why* the defaults are
what they are, [Security](@/docs/security.md) is the page to read.
