"""GraphQL endpoint discovery, introspection and batching."""
from __future__ import annotations

from core.http_client import HttpClient
from core.reporter import Finding
from . import common, evidence

PATHS = ("/graphql", "/api/graphql", "/v1/graphql")
JSON_HEADERS = {"Content-Type": "application/json"}
INTROSPECTION = {"query": "{__schema{types{name}}}"}


async def run(client: HttpClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    root = common.origin(base_url)
    for path in PATHS:
        url = root + path
        resp = await client.post(url, json=INTROSPECTION, headers=JSON_HEADERS)
        if not resp or resp.status >= 400:
            continue
        if "__schema" not in resp.body or "types" not in resp.body:
            continue

        findings.append(evidence.from_response(
            check="graphql",
            severity="medium",
            url=url,
            detail="GraphQL introspection aktif",
            resp=resp,
            payload=INTROSPECTION["query"],
        ))

        aliases = " ".join(f"a{i}:__typename" for i in range(50))
        batch = {"query": "query{" + aliases + "}"}
        batched = await client.post(url, json=batch, headers=JSON_HEADERS)
        if batched and batched.status == 200 and "a49" in batched.body:
            findings.append(evidence.from_response(
                check="graphql",
                severity="medium",
                url=url,
                detail="GraphQL batching 50 alias diterima",
                resp=batched,
                payload=batch["query"],
            ))
        break
    return findings
