"""TDD unit/integration regression checks for bounded auth throttling."""

import concurrent.futures

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app import auth
from app.main import app

pytestmark = pytest.mark.security

BASE = "/api/v1/auth"
BODY = {"email": "unknown@example.com", "password": "throttle-test-password"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREFLOW_DB", str(tmp_path / "throttle.db"))
    monkeypatch.setenv("SECUREFLOW_AUTH_LIMIT", "2")
    monkeypatch.setenv("SECUREFLOW_AUTH_WINDOW_SECONDS", "60")
    with TestClient(app) as client:
        yield client


@pytest.mark.integration
def test_login_throttles_brute_force_before_password_work(client, monkeypatch):
    calls = []
    monkeypatch.setattr(auth, "password_hash", lambda password: calls.append(password))
    assert client.post(BASE + "/login", json=BODY).status_code == 401
    assert client.post(BASE + "/login", json=BODY).status_code == 401
    response = client.post(BASE + "/login", json=BODY)
    assert response.status_code == 429
    assert response.json() == {"detail": "Too many authentication attempts. Try again later."}
    assert 1 <= int(response.headers["Retry-After"]) <= 60
    assert len(calls) == 2


@pytest.mark.integration
def test_registration_and_login_share_budget_and_ignore_forwarded_headers(client):
    assert client.post(BASE + "/login", json=BODY).status_code == 401
    assert client.post(BASE + "/login", json=BODY).status_code == 401
    response = client.post(
        BASE + "/register",
        json=BODY,
        headers={"X-Forwarded-For": "203.0.113.99", "Forwarded": "for=203.0.113.98"},
    )
    assert response.status_code == 429
    assert client.get("/health").status_code == 200


@pytest.mark.unit
def test_sliding_window_expires_without_sleep():
    now = [10.0]
    limiter = auth.RateLimiter(limit=2, window_seconds=60, clock=lambda: now[0])
    limiter.check("one")
    limiter.check("one")
    with pytest.raises(HTTPException) as exc:
        limiter.check("one")
    assert exc.value.status_code == 429
    limiter.check("two")  # Peers have independent budgets.
    now[0] = 70.0
    limiter.check("one")


@pytest.mark.unit
def test_peer_capacity_fails_closed_then_reclaims_expired_state():
    now = [0.0]
    limiter = auth.RateLimiter(limit=2, window_seconds=60, max_keys=2, clock=lambda: now[0])
    limiter.check("one")
    limiter.check("two")
    with pytest.raises(HTTPException) as exc:
        limiter.check("three")
    assert exc.value.status_code == 429
    assert len(limiter._buckets) == 2
    now[0] = 61
    limiter.check("three")
    assert len(limiter._buckets) == 1


@pytest.mark.unit
def test_parallel_attempts_cannot_exceed_limit():
    limiter = auth.RateLimiter(limit=3, window_seconds=60)

    def attempt(_):
        try:
            limiter.check("same-peer")
            return True
        except HTTPException:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt, range(20))) == 3


@pytest.mark.unit
@pytest.mark.parametrize("options", [dict(limit=0), dict(window_seconds=0), dict(max_keys=0)])
def test_invalid_limits_are_rejected(options):
    with pytest.raises(ValueError):
        auth.RateLimiter(**options)
