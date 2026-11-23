"""API schema discovery (OpenAPI/Swagger/GraphQL)."""
from __future__ import annotations

import json

from core.http_client import HttpClient
from core.reporter import Finding
from . import common, evidence

PATHS = (
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/v3/api-docs",
    "/api/swagger.json",
)
GRAPHQL_PATHS = ("/graphql", "/api/graphql")
JSON_HEADERS = {"Content-Type": "application/json"}


async def run(client: HttpClient, base_url: str) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    endpoints: set[str] = set()
    root = common.origin(base_url)

    for path in PATHS:
        url = root + path
        resp = await client.get(url)
        if not resp or resp.status != 200:
            continue
        try:
            data = json.loads(resp.body)
        except Exception:
            continue
        paths = data.get("paths") if isinstance(data, dict) else None
        if not isinstance(paths, dict):
            continue
        for route in paths:
            endpoints.add(root + route)
        findings.append(evidence.from_response(
            check="apischema",
            severity="info",
            url=url,
            detail=f"OpenAPI schema terekspos ({len(paths)} path)",
            resp=resp,
        ))
        break

    introspection = {"query": "{__schema{types{name}}}"}
    for path in GRAPHQL_PATHS:
        url = root + path
        resp = await client.post(url, json=introspection, headers=JSON_HEADERS)
        if resp and resp.status == 200 and "__schema" in resp.body:
            endpoints.add(url)
            break

    return findings, sorted(endpoints)
