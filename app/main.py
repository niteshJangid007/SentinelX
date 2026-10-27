"""Sentinelx authenticated orchestration API."""

import hashlib
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    HTTPException,
    UploadFile,
    Query,
    Response,
    Request,
)
from fastapi.middleware.cors import CORSMiddleware
from . import auth, db, schemas, scanner, admin, projects


@asynccontextmanager
async def lifespan(app):
    db.initialize()
    app.state.auth_limiter = auth.RateLimiter.from_environment()
    # An interrupted in-process worker must never leave a scan looking successful.
    with db.connect() as c:
        rows = c.execute("SELECT id,owner,data FROM resources WHERE kind='scan'").fetchall()
    import json

    for row in rows:
        data = json.loads(row["data"])
        if data.get("status") in ("queued", "running"):
            db.update(
                "scan",
                row["owner"],
                row["id"],
                {
                    "status": "failed",
                    "decision": "BLOCK",
                    "error": "Worker interrupted; rerun scan",
                },
            )
    yield


app = FastAPI(title="Sentinelx API", version="0.1.0", lifespan=lifespan)
from .errors import install_error_handlers

install_error_handlers(app)
app.include_router(admin.router)
app.include_router(projects.router)
origins = [s.strip() for s in os.getenv("SECUREFLOW_CORS_ORIGINS", "").split(",") if s.strip()]
if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
P = "/api/v1"


def required(kind, user, ident):
    item = db.get(kind, user["id"], ident)
    if item is None:
        raise HTTPException(404, "Resource not found")
    return item


def default_policy(user):
    policies = db.listing("policy", user["id"])
    return (
        policies[-1]
        if policies
        else db.create(
            "policy", user["id"], schemas.Policy(name="Default Release Policy").model_dump()
        )
    )


@app.get("/health")
def health():
    with db.connect() as c:
        c.execute("SELECT 1")
    return {"status": "ok", "service": "Sentinelx"}


@app.post(
    P + "/auth/register",
    status_code=201,
    dependencies=[Depends(auth.throttle_auth), Depends(auth.browser_auth_origin)],
)
def register(body: schemas.Credentials, response: Response):
    ident = str(uuid.uuid4())
    try:
        with db.connect() as c:
            c.execute(
                "INSERT INTO users VALUES(?,?,?,?)",
                (ident, body.email, auth.password_hash(body.password), "admin"),
            )
    except db.IntegrityError:
        raise HTTPException(409, "Account already exists")
    db.audit(ident, "account.registered", ident)
    return {
        "id": ident,
        "email": body.email,
        "role": "admin",
        **auth.issue_session(ident, response),
    }


@app.post(
    P + "/auth/login", dependencies=[Depends(auth.throttle_auth), Depends(auth.browser_auth_origin)]
)
def login(body: schemas.Credentials, response: Response):
    with db.connect() as c:
        user = c.execute(
            "SELECT u.*,COALESCE(uc.disabled,0) AS disabled FROM users u LEFT JOIN user_controls uc ON uc.user_id=u.id WHERE u.email=?",
            (body.email,),
        ).fetchone()
    # Perform a KDF even for unknown accounts to reduce account timing leakage.
    if not user:
        auth.password_hash(body.password)
        raise HTTPException(401, "Invalid credentials")
    if not auth.verify_password(body.password, user["password"]) or user["disabled"]:
        raise HTTPException(401, "Invalid credentials")
    db.audit(user["id"], "account.login", user["id"])
    return auth.issue_session(user["id"], response)


@app.get(P + "/auth/me")
def me(user=Depends(auth.current_user)):
    return user


@app.post(P + "/auth/logout", status_code=204)
def logout(request: Request, response: Response, user=Depends(auth.current_user)):
    with db.connect() as c:
        c.execute(
            "DELETE FROM sessions WHERE token_hash=?",
            (hashlib.sha256(request.state.session_token.encode()).hexdigest(),),
        )
    auth.clear_session_cookie(response)


@app.get(P + "/policies")
def policies(user=Depends(auth.current_user)):
    default_policy(user)
    return db.listing("policy", user["id"])


@app.post(P + "/policies", status_code=201)
def create_policy(body: schemas.Policy, user=Depends(auth.policy_writer)):
    item = db.create("policy", user["id"], body.model_dump())
    db.audit(user["id"], "policy.created", item["id"])
    return item


@app.put(P + "/policies/{ident}")
def update_policy(ident: str, body: schemas.Policy, user=Depends(auth.policy_writer)):
    required("policy", user, ident)
    item = db.update("policy", user["id"], ident, body.model_dump())
    db.audit(user["id"], "policy.updated", ident)
    return item


def run_scan(owner, scan_id, repository, policy, archive=None):
    db.update("scan", owner, scan_id, {"status": "running", "started_at": db.now()})
    try:
        effective = {**policy, "info": policy.get("informational", "ALLOW")}
        result = (
            scanner.scan_zip(archive, policy=effective)
            if archive is not None
            else scanner.scan_repository(repository["url"], repository["branch"], policy=effective)
        )
        findings = []
        for finding in result.get("findings", []):
            clean = {
                k: v for k, v in finding.items() if k not in ("id", "created_at", "updated_at")
            }
            findings.append(
                db.create(
                    "finding",
                    owner,
                    {
                        **clean,
                        "scan_id": scan_id,
                        "project_id": repository["project_id"],
                        "status": "open",
                    },
                )
            )
        result = {**result, "findings": findings, "completed_at": db.now()}
        # Missing engines are never represented as successful gates.
        incomplete = [
            g
            for g in result.get("gates", [])
            if str(g.get("status", "")).upper() not in ("PASS", "WARN", "BLOCK")
        ]
        decisions = [policy.get(str(f.get("severity", "")).lower(), "BLOCK") for f in findings]
        if any(str(g.get("status", "")).upper() == "BLOCK" for g in result.get("gates", [])):
            decisions.append("BLOCK")
        if any(str(g.get("status", "")).upper() == "WARN" for g in result.get("gates", [])):
            decisions.append("WARN")
        if result.get("status") != "completed":
            decisions.append("BLOCK")
        result["decision"] = (
            "BLOCK" if "BLOCK" in decisions else ("WARN" if "WARN" in decisions else "PASS")
        )
        if (
            incomplete
            or not result.get("gates")
            or result.get("coverage", {}).get("complete") is not True
        ):
            result["decision"] = "BLOCK"
            result["reasons"] = list(result.get("reasons", [])) + [
                "Required security gate coverage is incomplete."
            ]
        db.update("scan", owner, scan_id, result)
        db.audit(
            owner,
            "scan.completed" if result.get("status") == "completed" else "scan.failed",
            scan_id,
            result.get("decision", "BLOCK"),
        )
    except Exception:
        db.update(
            "scan",
            owner,
            scan_id,
            {
                "status": "failed",
                "decision": "BLOCK",
                "error": "Scan failed. Check server logs and retry.",
                "completed_at": db.now(),
            },
        )
        db.audit(owner, "scan.failed", scan_id, "failure")
        import logging

        logging.getLogger("secureflow").error(
            "Scan %s failed unexpectedly; diagnostic values redacted", scan_id
        )


from .resource_validation import serialized_mutation


@serialized_mutation
def queue_scan(user, repository, policy, tasks, archive=None):
    if repository.get("id"):
        repository = required("repository", user, repository["id"])
    required("project", user, repository["project_id"])
    active = [s for s in db.listing("scan", user["id"]) if s.get("status") in ("queued", "running")]
    if len(active) >= 2:
        raise HTTPException(429, "At most two active scans per account")
    item = db.create(
        "scan",
        user["id"],
        {
            "project_id": repository["project_id"],
            "repository_id": repository.get("id"),
            "source": "zip" if archive is not None else "github",
            "repository_url": repository.get("url"),
            "branch": repository.get("branch"),
            "status": "queued",
            "decision": "BLOCK",
            "policy": policy,
            "findings": [],
            "gates": [],
        },
    )
    db.audit(user["id"], "scan.started", item["id"])
    tasks.add_task(run_scan, user["id"], item["id"], repository, policy, archive)
    return item


@app.post(P + "/scans", status_code=202)
def start_scan(body: schemas.Scan, tasks: BackgroundTasks, user=Depends(auth.writer)):
    repo = required("repository", user, body.repository_id)
    policy = required("policy", user, body.policy_id) if body.policy_id else default_policy(user)
    return queue_scan(user, repo, policy, tasks)


@app.post(P + "/projects/{project_id}/upload", status_code=202)
async def upload(
    project_id: str, tasks: BackgroundTasks, file: UploadFile = File(...), user=Depends(auth.writer)
):
    required("project", user, project_id)
    limit = 20 * 1024 * 1024
    data = await file.read(limit + 1)
    await file.close()
    if len(data) > limit:
        raise HTTPException(413, "ZIP uploads must be at most 20 MiB")
    if not data.startswith(b"PK"):
        raise HTTPException(422, "A ZIP archive is required")
    return queue_scan(user, {"project_id": project_id}, default_policy(user), tasks, data)


@app.get(P + "/scans")
def scans(project_id: str | None = None, user=Depends(auth.current_user)):
    items = db.listing("scan", user["id"])
    return [s for s in items if not project_id or s.get("project_id") == project_id]


@app.get(P + "/scans/{ident}")
def scan(ident: str, user=Depends(auth.current_user)):
    return required("scan", user, ident)


@app.post(P + "/scans/{ident}/rerun", status_code=202)
def rerun(ident: str, tasks: BackgroundTasks, user=Depends(auth.writer)):
    item = required("scan", user, ident)
    if not item.get("repository_id"):
        raise HTTPException(409, "Upload the ZIP again to rescan")
    return queue_scan(
        user, required("repository", user, item["repository_id"]), item["policy"], tasks
    )


@app.get(P + "/scans/{ident}/report")
def report(ident: str, user=Depends(auth.current_user)):
    item = required("scan", user, ident)
    if item["status"] in ("queued", "running"):
        raise HTTPException(409, "Report is available after scan completion")
    db.audit(user["id"], "report.generated", ident)
    return {
        "report_version": "1.0",
        "generated_at": db.now(),
        "project": required("project", user, item["project_id"]),
        "scan": item,
        "deployment_allowed": item["status"] == "completed" and item.get("decision") == "PASS",
        "limitations": [
            "Heuristic scans are not a security certification. Review scanner coverage before release."
        ],
    }


@app.get(P + "/reports")
def reports(user=Depends(auth.current_user)):
    return [
        {
            "scan_id": s["id"],
            "project_id": s["project_id"],
            "decision": s.get("decision"),
            "risk_score": s.get("risk_score"),
            "completed_at": s.get("completed_at"),
        }
        for s in db.listing("scan", user["id"])
        if s["status"] in ("completed", "failed")
    ]


@app.get(P + "/findings")
def findings(
    project_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    user=Depends(auth.current_user),
):
    return [
        f
        for f in db.listing("finding", user["id"])
        if (not project_id or f.get("project_id") == project_id)
        and (not severity or f.get("severity", "").lower() == severity.lower())
        and (not status or f.get("status") == status)
    ]


@app.get(P + "/findings/{ident}")
def finding(ident: str, user=Depends(auth.current_user)):
    return required("finding", user, ident)


@app.patch(P + "/findings/{ident}")
def update_finding(ident: str, body: schemas.FindingUpdate, user=Depends(auth.policy_writer)):
    required("finding", user, ident)
    item = db.update(
        "finding", user["id"], ident, {"status": body.status, "review_reason": body.reason}
    )
    db.audit(user["id"], "finding." + body.status, ident)
    return item


@app.post(P + "/deployments", status_code=201)
def deployment(body: schemas.Deployment, user=Depends(auth.writer)):
    item = required("scan", user, body.scan_id)
    allowed = item["status"] == "completed" and item.get("decision") == "PASS"
    result = db.create(
        "deployment",
        user["id"],
        {
            **body.model_dump(),
            "project_id": item["project_id"],
            "decision": item.get("decision", "BLOCK"),
            "status": "eligible" if allowed else "blocked",
            "executed": False,
        },
    )
    db.audit(user["id"], "deployment.evaluated", result["id"], result["status"])
    return result


@app.get(P + "/deployments")
def deployments(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user=Depends(auth.current_user),
):
    return db.listing("deployment", user["id"])[offset : offset + limit]


@app.get(P + "/audit-logs")
def audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user=Depends(auth.current_user),
):
    return db.listing("audit", user["id"])[offset : offset + limit]


@app.get(P + "/dashboard")
def dashboard(user=Depends(auth.current_user)):
    scans = db.listing("scan", user["id"])
    findings = db.listing("finding", user["id"])
    return {
        "projects": len(db.listing("project", user["id"])),
        "total_scans": len(scans),
        "open_findings": sum(f.get("status") == "open" for f in findings),
        "blocked_releases": sum(
            d.get("status") == "blocked" for d in db.listing("deployment", user["id"])
        ),
        "severity_counts": {
            severity: sum(
                f.get("severity", "").lower() == severity and f.get("status") == "open"
                for f in findings
            )
            for severity in ["critical", "high", "medium", "low", "informational"]
        },
        "risk_trend": [
            {"scan_id": s["id"], "date": s.get("completed_at"), "risk_score": s.get("risk_score")}
            for s in reversed(scans)
            if s.get("completed_at")
        ],
    }


# The browser control panel uses the same origin and authenticated API endpoints.
from .web import mount_web

mount_web(app)
