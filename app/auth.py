import hashlib
import hmac
import math
import os
import threading
from collections import OrderedDict, deque
import secrets
import time
from fastapi import Depends, HTTPException, Request, Response
from urllib.parse import urlsplit
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from . import db

bearer = HTTPBearer(auto_error=False)


class RateLimiter:
    """Thread-safe, bounded single-process sliding window for authentication.

    Limits include successful requests: rotating usernames and endpoint switching
    cannot reset a peer's budget. Active peers are never evicted to make space.
    Use a shared ingress limiter before scaling to multiple workers or instances.
    """

    def __init__(self, limit=30, window_seconds=60, max_keys=10_000, clock=None):
        if (
            not isinstance(limit, int)
            or limit < 1
            or not isinstance(max_keys, int)
            or max_keys < 1
            or not math.isfinite(window_seconds)
            or window_seconds <= 0
        ):
            raise ValueError("Authentication rate limits must be positive finite values")
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.clock = clock or time.monotonic
        self._buckets = OrderedDict()
        self._lock = threading.Lock()

    @classmethod
    def from_environment(cls):
        return cls(
            limit=int(os.getenv("SECUREFLOW_AUTH_LIMIT", "30")),
            window_seconds=int(os.getenv("SECUREFLOW_AUTH_WINDOW_SECONDS", "60")),
            max_keys=int(os.getenv("SECUREFLOW_AUTH_MAX_PEERS", "10000")),
        )

    def _reject(self, retry_seconds):
        raise HTTPException(
            429,
            "Too many authentication attempts. Try again later.",
            headers={"Retry-After": str(max(1, math.ceil(retry_seconds)))},
        )

    def check(self, peer):
        with self._lock:
            now = self.clock()
            cutoff = now - self.window_seconds
            # Entries are ordered by last accepted attempt. Cleanup is amortized;
            # a flood of fresh peers cannot grow memory or evict active budgets.
            while self._buckets:
                oldest = next(iter(self._buckets))
                if self._buckets[oldest][-1] > cutoff:
                    break
                self._buckets.popitem(last=False)
            bucket = self._buckets.get(peer)
            if bucket is None:
                if len(self._buckets) >= self.max_keys:
                    oldest = next(iter(self._buckets.values()))
                    self._reject(oldest[-1] + self.window_seconds - now)
                bucket = deque()
                self._buckets[peer] = bucket
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                self._reject(bucket[0] + self.window_seconds - now)
            bucket.append(now)
            self._buckets.move_to_end(peer)


def throttle_auth(request: Request):
    # Never parse X-Forwarded-For/Forwarded here. Run Uvicorn with
    # --no-proxy-headers unless a separately secured ingress supplies identity.
    peer = request.client.host if request.client else "unknown-peer"
    request.app.state.auth_limiter.check(peer)


def password_hash(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return salt.hex() + ":" + digest.hex()


def verify_password(password, stored):
    salt, expected = stored.split(":")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
    return hmac.compare_digest(digest.hex(), expected)


SESSION_COOKIE = "sentinelx_session"
ADMIN_SESSION_COOKIE = "sentinelx_admin_session"
SESSION_SECONDS = 8 * 3600


def issue_session(user_id, response: Response | None = None, admin=False):
    token = secrets.token_urlsafe(48)
    with db.connect() as c:
        c.execute(
            "INSERT INTO sessions VALUES(?,?,?)",
            (hashlib.sha256(token.encode()).hexdigest(), user_id, time.time() + 8 * 3600),
        )
    if response is not None:
        response.set_cookie(
            ADMIN_SESSION_COOKIE if admin else SESSION_COOKIE,
            token,
            max_age=SESSION_SECONDS,
            httponly=True,
            secure=cookie_secure(),
            samesite="lax",
            path="/api/v1/admin" if admin else "/",
        )
    return {"access_token": token, "token_type": "bearer", "expires_in": SESSION_SECONDS}


def cookie_secure():
    return os.getenv("SECUREFLOW_COOKIE_SECURE", "false").lower() in ("1", "true", "yes")


def clear_session_cookie(response: Response, admin=False):
    response.delete_cookie(
        ADMIN_SESSION_COOKIE if admin else SESSION_COOKIE,
        path="/api/v1/admin" if admin else "/",
        httponly=True,
        secure=cookie_secure(),
        samesite="lax",
    )


def _origin(value):
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            return None
        return (
            parsed.scheme,
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
    except ValueError:
        return None


def check_browser_origin(request: Request, require_evidence=False):
    """Reject cross-origin browser writes, without trusting forwarded headers.

    PUBLIC_ORIGIN is the explicit external HTTPS origin behind a TLS proxy.
    Native bearer clients need no CSRF evidence; cookies require a browser's
    matching Origin or same-origin Fetch Metadata on unsafe requests.
    """
    origin = request.headers.get("origin")
    fetch_site = request.headers.get("sec-fetch-site")
    expected = (
        os.getenv("SECUREFLOW_PUBLIC_ORIGIN") or f"{request.url.scheme}://{request.url.netloc}"
    )
    if fetch_site and fetch_site != "same-origin":
        raise HTTPException(403, "Cross-origin authentication request rejected")
    if origin is not None and (_origin(origin) is None or _origin(origin) != _origin(expected)):
        raise HTTPException(403, "Cross-origin authentication request rejected")
    if require_evidence and origin is None and fetch_site != "same-origin":
        raise HTTPException(403, "Same-origin request evidence required")


def browser_auth_origin(request: Request):
    # Credentials endpoints also reject login CSRF before replacing a session.
    check_browser_origin(request)


def current_user(
    request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)
):
    if credentials is not None:
        token = credentials.credentials
    elif request.headers.get("authorization"):
        raise HTTPException(401, "Invalid authorization header")
    else:
        cookie = (
            ADMIN_SESSION_COOKIE
            if request.url.path.startswith("/api/v1/admin/")
            else SESSION_COOKIE
        )
        token = request.cookies.get(cookie)
        if token and request.method not in ("GET", "HEAD", "OPTIONS"):
            check_browser_origin(request, require_evidence=True)
    if not token:
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
    digest = hashlib.sha256(token.encode()).hexdigest()
    with db.connect() as c:
        user = c.execute(
            "SELECT u.id,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN user_controls uc ON uc.user_id=u.id WHERE s.token_hash=? AND s.expires>? AND COALESCE(uc.disabled,0)=0",
            (digest, time.time()),
        ).fetchone()
    if not user:
        raise HTTPException(401, "Session invalid or expired")
    request.state.session_token = token
    return dict(user)


def writer(user=Depends(current_user)):
    if user["role"] not in ("admin", "security_analyst", "developer"):
        raise HTTPException(403, "Write permission required")
    return user


def policy_writer(user=Depends(current_user)):
    if user["role"] not in ("admin", "security_analyst"):
        raise HTTPException(403, "Policy administration permission required")
    return user
