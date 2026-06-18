#!/usr/bin/env python3
# Copyright (C) 2026 Ycarus (Yannick Chabanois) <ycarus@zugaina.org> for OpenMPTCProuter
# SPDX-License-Identifier: AGPL-3.0
#
# Standalone single-user wrapper for omr_metrics.py.
# Runs the metrics + decision engine without omradmin.py.
#
# Auth
# ----
# HTTP Basic (default): credentials must match OMR_USER / OMR_PASS env vars.
# No-auth (dev):        set OMR_NOAUTH=1 to skip auth entirely.
#
# Usage
# -----
#   pip install fastapi uvicorn
#   OMR_USER=admin OMR_PASS=secret python omr_metrics_standalone.py
#   OMR_NOAUTH=1 uvicorn omr_metrics_standalone:app --port 8080

import os
import argparse
import secrets
import logging
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

import omr_metrics

LOG = logging.getLogger("uvicorn.error")

_NOAUTH = os.getenv("OMR_NOAUTH", "").strip() in ("1", "true", "yes")
_USER   = os.getenv("OMR_USER", "admin")
_PASS   = os.getenv("OMR_PASS", "changeme")

_THE_USER = None   # built after env vars are read (see below)


class User(BaseModel):
    username: str
    permissions: str = "admin"


_security = HTTPBasic(auto_error=not _NOAUTH)


async def get_current_user(
    credentials: Optional[HTTPBasicCredentials] = Depends(_security),
) -> User:
    if _NOAUTH:
        return _THE_USER
    ok = (
        secrets.compare_digest(credentials.username, _USER)
        and secrets.compare_digest(credentials.password, _PASS)
    )
    if not ok:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return _THE_USER


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    return current_user


app = FastAPI(
    title="OMR Metrics (standalone)",
    description="omr_metrics decision engine and storage, running without omradmin.py",
    version="1.0.0",
)

_THE_USER = User(username=_USER, permissions="admin")

app.include_router(
    omr_metrics.create_router(get_current_user, get_current_active_user, User)
)


@app.get("/", include_in_schema=False)
async def root():
    return {"service": "omr_metrics_standalone", "docs": "/docs"}


if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description="OMR Metrics standalone server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if _NOAUTH:
        LOG.warning("OMR_NOAUTH=1: authentication disabled")
    else:
        LOG.info("Auth: user=%r  (OMR_USER / OMR_PASS to change)", _USER)

    uvicorn.run("omr_metrics_standalone:app", host=args.host, port=args.port, reload=args.reload)
