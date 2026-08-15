"""Keeping activities on separate Tor circuits.

Two requests sharing a circuit leave the network from the same exit relay at
the same moment, and are therefore linkable. Isolation decides which of your
activities are allowed to be linked.

    python examples/isolation.py
"""

import hypertor


def main() -> None:
    # "per_request" gives every request its own circuit: the strongest
    # separation, and the slowest, since no connection can ever be reused.
    with hypertor.Client(timeout=120, isolation="per_request") as client:
        for label in ("first", "second", "third"):
            payload = client.get("https://check.torproject.org/api/ip").json()
            print(f"{label:7} request exits from {payload['IP']}")

    # "per_host" — the default — reuses a warm circuit per destination while
    # still keeping different destinations apart.
    print("\nwith the default per-host isolation, repeat requests reuse a circuit:")
    with hypertor.Client(timeout=120) as client:
        for label in ("first", "second"):
            payload = client.get("https://check.torproject.org/api/ip").json()
            print(f"{label:7} request exits from {payload['IP']}")

    # Explicit tokens give the finest control: two personas that must never be
    # linkable, each pinned to its own circuit for as long as you keep the
    # token around.
    print("\nexplicit tokens keep two personas apart:")
    alice = hypertor.IsolationToken()
    bob = hypertor.IsolationToken()

    with hypertor.Client(timeout=120, isolation="none") as client:
        for name, token in (("alice", alice), ("bob", bob), ("alice", alice)):
            payload = client.get("https://check.torproject.org/api/ip", isolation=token).json()
            print(f"{name:5} exits from {payload['IP']}")


if __name__ == "__main__":
    main()
