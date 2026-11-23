"""WAF fingerprinting."""
from __future__ import annotations

from core.http_client import HttpClient

SIGNATURES = [
    ("Cloudflare", ("cf-ray", "cloudflare")),
    ("Sucuri", ("x-sucuri-id", "x-sucuri-cache", "sucuri")),
    ("Akamai", ("akamaighost", "x-akamai", "akamai")),
    ("Imperva/Incapsula", ("incap_ses", "visid_incap", "x-iinfo", "incapsula")),
    ("AWS WAF/ALB", ("awselb", "x-amzn-requestid", "awswaf")),
    ("F5 BIG-IP", ("bigip", "x-wa-info")),
    ("ModSecurity", ("mod_security", "modsecurity", "not acceptable")),
    ("Fastly", ("x-fastly", "fastly")),
]

PROBE = "/?id=%27%20OR%201%3D1--"


async def run(client: HttpClient, base_url: str) -> str:
    root = base_url.rstrip("/")
    resp = await client.get(root + PROBE)
    if not resp:
        return ""
    blob = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
    blob += " " + resp.body.lower()[:800]
    for name, needles in SIGNATURES:
        if any(needle in blob for needle in needles):
            return name
    if resp.status in (403, 406, 429, 501):
        return "unknown (payload diblokir)"
    return ""
