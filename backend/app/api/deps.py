from __future__ import annotations

from fastapi import HTTPException, Request

from app.core.container import AppContainer


def get_container(request: Request) -> AppContainer:
    container = getattr(request.app.state, "container", None)
    if container is None:
        raise HTTPException(status_code=503, detail="Application container is not initialized")
    return container


def client_key(request: Request) -> str:
    return request.client.host if request.client else "local"
