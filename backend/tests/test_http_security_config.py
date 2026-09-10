"""Unit/config-level tests for Step 11L's HTTP security boundary
settings and middleware behavior. No database required.

Two layers are tested:

1. app.core.config.Settings parsing/validation for cors_allowed_origins
   / trusted_hosts (§19 of the brief: explicit origin, explicit host,
   multiple origins, dev config, invalid config, empty config, no
   accidental wildcard fallback).

2. CORSMiddleware / TrustedHostMiddleware behavior through a throwaway
   FastAPI app, built with different origin/host lists per test.
   Deliberately NOT tested against the real app.main:app: that app's
   CORS/TrustedHost middleware instances are constructed once, at
   module-import time, with `allow_origins`/`allowed_hosts` baked in as
   plain constructor arguments (mirroring how Step 11I's
   RequestBodySizeLimitMiddleware's max_bytes is fixed at construction
   time, not read fresh per request) -- mutating the cached Settings
   instance afterward has no effect on an already-constructed middleware
   instance. A throwaway app gives the same real Starlette middleware
   behavior with a deterministic, per-test-controlled origin/host list.
   Behavior against the REAL app (its actual default empty-origins/
   testserver-inclusive config, interaction with auth/RBAC/business
   logic) is covered separately in tests/test_http_security_api.py.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.core.config import Settings

# =============================================================================
# Settings parsing/validation
# =============================================================================


def test_explicit_cors_origin_is_parsed():
    settings = Settings(cors_allowed_origins="http://localhost:5173")

    assert settings.cors_allowed_origins_list == ["http://localhost:5173"]


def test_explicit_trusted_host_is_parsed():
    settings = Settings(trusted_hosts="api.example.com")

    assert settings.trusted_hosts_list == ["api.example.com"]


def test_multiple_cors_origins_are_parsed():
    settings = Settings(cors_allowed_origins="http://localhost:5173,http://localhost:3000")

    assert settings.cors_allowed_origins_list == ["http://localhost:5173", "http://localhost:3000"]


def test_multiple_trusted_hosts_are_parsed():
    settings = Settings(trusted_hosts="api.example.com,admin.example.com")

    assert settings.trusted_hosts_list == ["api.example.com", "admin.example.com"]


def test_development_default_trusted_hosts_includes_local_and_test_hosts():
    """The default (no TRUSTED_HOSTS env var set) must keep local
    development and this test suite itself working -- localhost/
    127.0.0.1 for interactive dev, "testserver" because that is
    Starlette TestClient's own default Host header (verified
    empirically during Step 11L discovery, not guessed).
    """
    settings = Settings()

    assert "localhost" in settings.trusted_hosts_list
    assert "127.0.0.1" in settings.trusted_hosts_list
    assert "testserver" in settings.trusted_hosts_list


def test_development_default_cors_origins_is_empty():
    """Step 11L: no frontend existed in this repository at the time,
    so the safe default was to permit no cross-origin browser request
    at all until an operator explicitly configured a real origin. The
    empty-by-default DESIGN (Settings.cors_allowed_origins itself,
    unchanged) is still exactly what this test verifies -- via a fresh
    Settings() constructed with no env override, matching a clean
    checkout with no local .env at all.

    Step 12A: this repository's own local backend/.env (git-ignored,
    developer-specific -- see that file's own comments) now sets
    CORS_ALLOWED_ORIGINS to the real AMNIX frontend's Vite dev origin,
    since that frontend now genuinely exists and needs it -- exactly
    the scenario this docstring already described as the intended way
    to leave the empty default behind ("until an operator explicitly
    configures a real origin"). That is a local, non-default override,
    not a change to the default this test verifies, so `env_file=None`
    is used here to construct Settings from process environment
    variables only, deliberately bypassing this developer's local
    .env file.
    """
    settings = Settings(_env_file=None)

    assert settings.cors_allowed_origins_list == []


def test_wildcard_cors_origin_is_rejected_at_construction():
    with pytest.raises(ValueError, match="CORS_ALLOWED_ORIGINS"):
        Settings(cors_allowed_origins="*")


def test_wildcard_trusted_host_is_rejected_at_construction():
    with pytest.raises(ValueError, match="TRUSTED_HOSTS"):
        Settings(trusted_hosts="*")


def test_wildcard_mixed_with_real_origins_is_still_rejected():
    """A partial wildcard (e.g. someone appending '*' to an otherwise
    valid list) must still fail -- the check is "contains '*' anywhere",
    not "is exactly '*'".
    """
    with pytest.raises(ValueError, match="CORS_ALLOWED_ORIGINS"):
        Settings(cors_allowed_origins="http://localhost:5173,*")


def test_empty_cors_configuration_never_produces_a_wildcard():
    settings = Settings(cors_allowed_origins="")

    assert settings.cors_allowed_origins_list == []
    assert "*" not in settings.cors_allowed_origins_list


def test_empty_string_entries_are_dropped_not_treated_as_wildcard():
    settings = Settings(cors_allowed_origins="http://localhost:5173,,")

    assert settings.cors_allowed_origins_list == ["http://localhost:5173"]


# =============================================================================
# CORS middleware behavior (throwaway app, deterministic origin list)
# =============================================================================


def _build_cors_app(allowed_origins: list[str]) -> FastAPI:
    app = FastAPI()

    @app.post("/echo")
    def echo() -> dict:
        return {"ok": True}

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization"],
        allow_credentials=False,
    )
    return app


def test_allowed_configured_origin_receives_cors_permission():
    app = _build_cors_app(["http://localhost:5173"])
    with TestClient(app) as client:
        response = client.post("/echo", headers={"Origin": "http://localhost:5173"})

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_disallowed_origin_does_not_receive_cors_permission():
    app = _build_cors_app(["http://localhost:5173"])
    with TestClient(app) as client:
        response = client.post("/echo", headers={"Origin": "http://evil.example.com"})

    # The server still processes the request (CORS is enforced by the
    # browser reading response headers, not the server refusing it) --
    # what matters is the PERMISSION header's absence.
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_preflight_from_allowed_origin_succeeds():
    app = _build_cors_app(["http://localhost:5173"])
    with TestClient(app) as client:
        response = client.options(
            "/echo",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization",
            },
        )

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "POST" in response.headers.get("access-control-allow-methods", "")


def test_preflight_from_disallowed_origin_does_not_receive_permission():
    app = _build_cors_app(["http://localhost:5173"])
    with TestClient(app) as client:
        response = client.options(
            "/echo",
            headers={
                "Origin": "http://evil.example.com",
                "Access-Control-Request-Method": "POST",
            },
        )

    assert response.headers.get("access-control-allow-origin") != "http://evil.example.com"


def test_multiple_configured_origins_each_work_independently():
    app = _build_cors_app(["http://localhost:5173", "http://localhost:3000"])
    with TestClient(app) as client:
        first = client.post("/echo", headers={"Origin": "http://localhost:5173"})
        second = client.post("/echo", headers={"Origin": "http://localhost:3000"})
        third = client.post("/echo", headers={"Origin": "http://localhost:9999"})

    assert first.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert second.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "access-control-allow-origin" not in third.headers


def test_empty_origin_list_permits_nothing():
    app = _build_cors_app([])
    with TestClient(app) as client:
        response = client.post("/echo", headers={"Origin": "http://localhost:5173"})

    assert "access-control-allow-origin" not in response.headers


def test_cors_response_never_sets_allow_credentials():
    """allow_credentials=False throughout AMNIX (see app.main's own
    docstring) -- verified directly, not just configured.
    """
    app = _build_cors_app(["http://localhost:5173"])
    with TestClient(app) as client:
        response = client.post("/echo", headers={"Origin": "http://localhost:5173"})

    assert "access-control-allow-credentials" not in response.headers


# =============================================================================
# TrustedHost middleware behavior (throwaway app, deterministic host list)
# =============================================================================


def _build_trusted_host_app(allowed_hosts: list[str]) -> FastAPI:
    app = FastAPI()

    @app.get("/echo")
    def echo() -> dict:
        return {"ok": True}

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts, www_redirect=False)
    return app


def test_configured_host_succeeds():
    app = _build_trusted_host_app(["api.example.com"])
    with TestClient(app, base_url="http://api.example.com") as client:
        response = client.get("/echo")

    assert response.status_code == 200


def test_localhost_works_in_development_configuration():
    app = _build_trusted_host_app(["localhost", "127.0.0.1", "testserver"])
    with TestClient(app, base_url="http://localhost") as client:
        response = client.get("/echo")

    assert response.status_code == 200


def test_127_0_0_1_works_in_development_configuration():
    app = _build_trusted_host_app(["localhost", "127.0.0.1", "testserver"])
    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.get("/echo")

    assert response.status_code == 200


def test_invalid_host_is_rejected():
    app = _build_trusted_host_app(["api.example.com"])
    with TestClient(app) as client:  # default base_url -> Host: testserver, not allowed here
        response = client.get("/echo")

    assert response.status_code == 400


def test_invalid_host_response_does_not_leak_configured_hosts():
    app = _build_trusted_host_app(["api.example.com", "admin-internal.example.com"])
    with TestClient(app) as client:
        response = client.get("/echo")

    assert "api.example.com" not in response.text
    assert "admin-internal.example.com" not in response.text
    assert response.text == "Invalid host header"
