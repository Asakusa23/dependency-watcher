from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

from app.api.deps import client_key
from app.core.container import AppContainer


logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware:
    def __init__(self, app) -> None:  # noqa: ANN001
        self.app = app

    async def __call__(self, scope, receive, send):  # noqa: ANN001
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):  # noqa: ANN001
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                headers.setdefault(b"x-content-type-options", b"nosniff")
                headers.setdefault(b"x-frame-options", b"DENY")
                headers.setdefault(b"referrer-policy", b"no-referrer")
                headers.setdefault(b"permissions-policy", b"camera=(), microphone=(), geolocation=()")
                message["headers"] = list(headers.items())
            await send(message)

        await self.app(scope, receive, send_wrapper)


class ContentLengthLimitMiddleware:
    def __init__(self, app, limit_bytes: int) -> None:  # noqa: ANN001
        self.app = app
        self.limit_bytes = limit_bytes

    async def __call__(self, scope, receive, send):  # noqa: ANN001
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            raw_length = headers.get(b"content-length")
            if raw_length:
                try:
                    length = int(raw_length)
                except ValueError:
                    length = 0
                if length > self.limit_bytes + 1024 * 1024:
                    response = JSONResponse(
                        status_code=413,
                        content={"detail": "Request body exceeds the configured upload limit"},
                    )
                    await response(scope, receive, send)
                    return
        await self.app(scope, receive, send)


class RateLimitMiddleware:
    def __init__(self, app, container: AppContainer) -> None:  # noqa: ANN001
        self.app = app
        self.container = container

    async def __call__(self, scope, receive, send):  # noqa: ANN001
        if scope["type"] != "http" or scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if not path.startswith("/api") or path in {"/api/health", "/api/settings"}:
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        client = scope.get("client")
        host = client[0] if client else "local"
        cost = 1.0
        if path == "/api/scans" and scope.get("method") == "POST":
            cost = 5.0
        elif path == "/api/scans/upload":
            cost = 10.0
        allowed, retry_after = self.container.global_limiter.allow(host, cost)
        if not allowed:
            request = Request(scope, receive)
            response = JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again shortly."},
                headers={"Retry-After": str(int(retry_after) + 1)},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
