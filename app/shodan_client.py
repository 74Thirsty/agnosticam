from __future__ import annotations

import json
from urllib.parse import quote_plus
from urllib.request import urlopen

from app.models import ShodanHost


class ShodanClient:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key.strip()
        if not self.api_key:
            raise ValueError("Shodan API key is required")

    def search(self, query: str, *, limit: int = 25) -> list[ShodanHost]:
        q = quote_plus(query)
        url = f"https://api.shodan.io/shodan/host/search?key={self.api_key}&query={q}&minify=false"
        with urlopen(url, timeout=20) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))

        results: list[ShodanHost] = []
        for match in payload.get("matches", [])[:limit]:
            loc = match.get("location") or {}
            city = loc.get("city")
            country = loc.get("country_name")
            parts = [p for p in [city, country] if p]
            location = ", ".join(parts) if parts else None
            results.append(
                ShodanHost(
                    ip_address=match.get("ip_str", ""),
                    port=int(match.get("port") or 0),
                    transport=str(match.get("transport") or "tcp"),
                    org=match.get("org"),
                    isp=match.get("isp"),
                    os=match.get("os"),
                    hostnames=tuple(match.get("hostnames") or ()),
                    domains=tuple(match.get("domains") or ()),
                    product=match.get("product"),
                    title=(match.get("http") or {}).get("title") if isinstance(match.get("http"), dict) else None,
                    location=location,
                    timestamp=None,
                )
            )
        return [r for r in results if r.ip_address]
