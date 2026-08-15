"""Concurrent requests over Tor with asyncio.

python examples/async_client.py
"""

import asyncio

import hypertor


async def main() -> None:
    async with hypertor.AsyncClient(timeout=120) as client:
        # These run concurrently over separate circuits, so the total time is
        # roughly that of the slowest request rather than their sum.
        urls = [
            "https://check.torproject.org/api/ip",
            "https://httpbin.org/uuid",
            "https://httpbin.org/user-agent",
        ]

        responses = await asyncio.gather(*(client.get(url) for url in urls))

        for url, response in zip(urls, responses, strict=True):
            print(f"{response.status_code}  {url}")


if __name__ == "__main__":
    asyncio.run(main())
