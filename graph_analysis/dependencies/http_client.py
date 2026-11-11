from __future__ import annotations

import datetime as dt
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


USER_AGENT = "graph-analysis-pipeline"


class HttpClient:
    def __init__(
        self,
        token: str | None = None,
        default_headers: dict[str, str] | None = None,
        timeout: int = 60,
        retries: int = 3,
        cafile: str | Path | None = None,
    ) -> None:
        self.token = token
        self.default_headers = default_headers or {}
        self.timeout = timeout
        self.retries = retries
        self.ssl_context = _ssl_context(cafile)
        self.retry_events: list[dict[str, Any]] = []

    def request_json(
        self,
        url: str,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        body: bytes | None = None
        request_headers = {
            "User-Agent": USER_AGENT,
            **self.default_headers,
            **(headers or {}),
        }
        if self.token:
            request_headers.setdefault("Authorization", f"Bearer {self.token}")
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")

        response = self._open_with_retries(url, method, body, request_headers)
        text = response.read().decode("utf-8")
        return json.loads(text) if text else None

    def download_file(self, url: str, target: Path) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        response = self._open_with_retries(
            url,
            "GET",
            None,
            {"User-Agent": USER_AGENT},
        )
        with target.open("wb") as handle:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)

    def _open_with_retries(
        self,
        url: str,
        method: str,
        body: bytes | None,
        headers: dict[str, str],
    ) -> urllib.response.addinfourl:
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            request = urllib.request.Request(url, data=body, headers=headers, method=method)
            try:
                return urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context)
            except urllib.error.HTTPError as exc:
                last_error = exc
                retry_after = exc.headers.get("Retry-After")
                reset_at = exc.headers.get("X-RateLimit-Reset")
                if exc.code in {403, 429, 500, 502, 503, 504} and attempt < self.retries:
                    sleep_for = 2**attempt
                    if retry_after and retry_after.isdigit():
                        sleep_for = max(sleep_for, int(retry_after))
                    elif reset_at and reset_at.isdigit():
                        sleep_for = max(sleep_for, int(reset_at) - int(time.time()) + 1)
                    sleep_for = min(max(sleep_for, 1), 120)
                    self.retry_events.append(
                        {
                            "url": url,
                            "status": exc.code,
                            "attempt": attempt + 1,
                            "sleep_seconds": sleep_for,
                            "recorded_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                        }
                    )
                    time.sleep(sleep_for)
                    continue
                error_body = exc.read().decode("utf-8", errors="replace")[:1000]
                raise RuntimeError(f"HTTP {exc.code} for {url}: {error_body}") from exc
            except urllib.error.URLError as exc:
                last_error = exc
                if _is_ssl_certificate_error(exc):
                    raise RuntimeError(
                        f"TLS certificate verification failed for {url}. "
                        "Install the pinned dependencies (`python3 -m pip install -r requirements.txt`) "
                        "so the collector can use certifi's CA bundle, or set SSL_CERT_FILE/REQUESTS_CA_BUNDLE "
                        f"to a valid CA bundle. Original error: {exc}"
                    ) from exc
                if attempt < self.retries:
                    time.sleep(2**attempt)
                    continue
                raise RuntimeError(f"Request failed for {url}: {exc}") from exc
        raise RuntimeError(f"Request failed for {url}: {last_error}")


def add_query(url: str, params: dict[str, Any]) -> str:
    parsed = urllib.parse.urlparse(url)
    existing = dict(urllib.parse.parse_qsl(parsed.query))
    existing.update({key: str(value) for key, value in params.items() if value is not None})
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(existing)))


def _ssl_context(cafile: str | Path | None = None) -> ssl.SSLContext:
    explicit_cafile = str(cafile) if cafile else os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    explicit_capath = os.environ.get("SSL_CERT_DIR")
    if explicit_cafile or explicit_capath:
        return ssl.create_default_context(cafile=explicit_cafile, capath=explicit_capath)

    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def _is_ssl_certificate_error(exc: urllib.error.URLError) -> bool:
    reason = getattr(exc, "reason", None)
    return (
        isinstance(reason, ssl.SSLCertVerificationError)
        or (isinstance(reason, ssl.SSLError) and "CERTIFICATE_VERIFY_FAILED" in str(reason))
        or "CERTIFICATE_VERIFY_FAILED" in str(exc)
    )
