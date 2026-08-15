"""Making HTTP requests over Tor.

    python python_examples/client.py
"""

import hypertor


def main() -> None:
    # Bootstrapping downloads a Tor directory; the first run takes a while.
    print("bootstrapping Tor...")

    with hypertor.Client(timeout=120) as client:
        # Confirm the traffic really is going through Tor.
        response = client.get("https://check.torproject.org/api/ip")
        payload = response.json()
        print(f"exiting from {payload['IP']} (IsTor={payload['IsTor']})")

        # Onion services need no exit relay at all.
        response = client.get(
            "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"
        )
        print(f"DuckDuckGo onion: {response.status_code}, {len(response)} bytes")

        # POST with JSON.
        response = client.post(
            "https://httpbin.org/post",
            json={"hello": "tor"},
        )
        print(f"echoed back: {response.json()['json']}")


if __name__ == "__main__":
    main()
