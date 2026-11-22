"""DOM-based XSS probing via a headless browser (optional)."""
from __future__ import annotations

import asyncio

from core.http_client import HttpClient
from core.reporter import Finding
from . import common, evidence

PAYLOAD = "<svg/onload=alert(1)>"
TIMEOUT_MS = 5000


def _candidates(url: str):
    yield url + ("#" if "#" not in url else "") + PAYLOAD
    for key in common.param_keys(url):
        yield common.inject(url, key, PAYLOAD)


async def _playwright(pages: list[str]) -> list[Finding]:
    from playwright.async_api import async_playwright

    findings: list[Finding] = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        page = await browser.new_page()
        alerts: list[str] = []
        page.on("dialog", lambda d: (alerts.append(d.message), asyncio.ensure_future(d.dismiss())))
        for url in pages[:10]:
            for candidate in _candidates(url):
                alerts.clear()
                try:
                    await page.goto(candidate, timeout=TIMEOUT_MS)
                except Exception:
                    continue
                if alerts:
                    findings.append(evidence.raw(
                        check="domxss",
                        severity="high",
                        url=candidate,
                        detail=f"DOM XSS: alert({alerts[0]!r}) terpicu",
                        request=f"GET {candidate}",
                        response=f"dialog: {alerts[0]}",
                        payload=PAYLOAD,
                    ))
                    break
        await browser.close()
    return findings


def _selenium(pages: list[str]) -> list[Finding]:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options

    options = Options()
    options.add_argument("--headless=new")
    driver = webdriver.Chrome(options=options)
    findings: list[Finding] = []
    try:
        for url in pages[:10]:
            for candidate in _candidates(url):
                try:
                    driver.get(candidate)
                    alert = driver.switch_to.alert
                except Exception:
                    continue
                text = alert.text
                alert.dismiss()
                findings.append(evidence.raw(
                    check="domxss",
                    severity="high",
                    url=candidate,
                    detail=f"DOM XSS: alert({text!r}) terpicu",
                    request=f"GET {candidate}",
                    response=f"alert: {text}",
                    payload=PAYLOAD,
                ))
                break
    finally:
        driver.quit()
    return findings


async def run(client: HttpClient, pages: list[str]) -> list[Finding]:
    try:
        import playwright  # noqa: F401
        return await _playwright(pages)
    except Exception:
        pass
    try:
        import selenium  # noqa: F401
        return await asyncio.to_thread(_selenium, pages)
    except Exception:
        return []
