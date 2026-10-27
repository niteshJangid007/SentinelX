"""Operator-only platform administration; workspace admins are not operators."""

import json
import hashlib
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Response, Request
from pydantic import model_validator
from . import auth, db, schemas

router = APIRouter(prefix="/api/v1/admin", tags=["Platform administration"])


def platform_admin(user=Depends(auth.current_user)):
    with db.connect() as c:
        member = c.execute(
            "SELECT user_id FROM platform_admins WHERE user_id=?", (user["id"],)
        ).fetchone()
    if not member:
        raise HTTPException(403, "Platform administrator permission required")
    return user


@router.post(
    "/auth/login", dependencies=[Depends(auth.throttle_auth), Depends(auth.browser_auth_origin)]
)
def login(body: schemas.Credentials, response: Response):
    with db.connect() as c:
        user = c.execute(
            "SELECT u.*,p.user_id AS platform_id,COALESCE(uc.disabled,0) AS disabled FROM users u LEFT JOIN platform_admins p ON p.user_id=u.id LEFT JOIN user_controls uc ON uc.user_id=u.id WHERE u.email=?",
            (body.email,),
        ).fetchone()
    valid = (
        auth.verify_password(body.password, user["password"])
        if user
        else bool(auth.password_hash(body.password)) and False
    )
    if not valid or not user["platform_id"] or user["disabled"]:
        raise HTTPException(401, "Invalid administrator credentials")
    db.audit(user["id"], "admin.login", user["id"])
    return auth.issue_session(user["id"], response, admin=True)


@router.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response, user=Depends(auth.current_user)):
    with db.connect() as c:
        c.execute(
            "DELETE FROM sessions WHERE token_hash=?",
            (hashlib.sha256(request.state.session_token.encode()).hexdigest(),),
        )
    auth.clear_session_cookie(response, admin=True)


@router.get("/me")
def me(user=Depends(platform_admin)):
    return {**user, "platform_admin": True}


def safe_user(row):
    return {
        "id": row["id"],
        "email": row["email"],
        "role": row["role"],
        "disabled": bool(row["disabled"]),
        "platform_admin": bool(row["platform_id"]),
    }


@router.get("/overview")
def overview(user=Depends(platform_admin)):
    with db.connect() as c:
        count = c.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        rows = c.execute("SELECT kind,COUNT(*) AS count FROM resources GROUP BY kind").fetchall()
    counts = {r["kind"]: r["count"] for r in rows}
    db.audit(user["id"], "admin.overview.read", "platform")
    return {
        "users": count,
        "projects": counts.get("project", 0),
        "repositories": counts.get("repository", 0),
        "scans": counts.get("scan", 0),
        "findings": counts.get("finding", 0),
        "audit_logs": counts.get("audit", 0),
    }


@router.get("/users")
def users(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user=Depends(platform_admin),
):
    with db.connect() as c:
        rows = c.execute(
            "SELECT u.id,u.email,u.role,p.user_id AS platform_id,COALESCE(uc.disabled,0) AS disabled FROM users u LEFT JOIN platform_admins p ON p.user_id=u.id LEFT JOIN user_controls uc ON uc.user_id=u.id ORDER BY u.email LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    db.audit(user["id"], "admin.users.read", "users")
    return [safe_user(r) for r in rows]


class UserUpdate(schemas.Input):
    role: Literal["admin", "security_analyst", "developer", "viewer"] | None = None
    disabled: bool | None = None

    @model_validator(mode="after")
    def nonempty(self):
        if self.role is None and self.disabled is None:
            raise ValueError("A role or disabled state is required")
        return self


@router.patch("/users/{ident}")
def update_user(ident: str, body: UserUpdate, user=Depends(platform_admin)):
    with db.connect() as c:
        row = c.execute(
            "SELECT u.id,u.email,u.role,p.user_id AS platform_id,COALESCE(uc.disabled,0) AS disabled FROM users u LEFT JOIN platform_admins p ON p.user_id=u.id LEFT JOIN user_controls uc ON uc.user_id=u.id WHERE u.id=?",
            (ident,),
        ).fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        if row["platform_id"]:
            raise HTTPException(
                409, "Platform administrator accounts must be managed by a local operator"
            )
        if body.role is not None:
            c.execute("UPDATE users SET role=? WHERE id=?", (body.role, ident))
        if body.disabled is not None:
            c.execute(
                "INSERT INTO user_controls(user_id,disabled) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET disabled=excluded.disabled",
                (ident, int(body.disabled)),
            )
            if body.disabled:
                c.execute("DELETE FROM sessions WHERE user_id=?", (ident,))
    db.audit(user["id"], "admin.user.updated", ident)
    return {**safe_user(row), **body.model_dump(exclude_none=True)}


COLLECTIONS = {
    "projects": "project",
    "repositories": "repository",
    "scans": "scan",
    "findings": "finding",
    "audit-logs": "audit",
}


def resource(kind, ident):
    with db.connect() as c:
        row = c.execute(
            "SELECT owner,data FROM resources WHERE kind=? AND id=?", (kind, ident)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Resource not found")
    return {**json.loads(row["data"]), "owner_id": row["owner"]}


@router.get("/scans/{ident}/report")
def report(ident: str, user=Depends(platform_admin)):
    scan = resource("scan", ident)
    if scan.get("status") not in ("completed", "failed"):
        raise HTTPException(409, "Report is available after scan completion")
    project = resource("project", scan["project_id"])
    db.audit(user["id"], "admin.report.read", ident)
    return {
        "report_version": "1.0",
        "generated_at": db.now(),
        "project": project,
        "scan": scan,
        "deployment_allowed": scan.get("status") == "completed" and scan.get("decision") == "PASS",
        "limitations": [
            "Inspect actual engine coverage; heuristic results are not security certification."
        ],
    }


@router.get("/reports")
def reports(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user=Depends(platform_admin),
):
    with db.connect() as c:
        rows = c.execute(
            "SELECT owner,data FROM resources WHERE kind='scan' ORDER BY id LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    result = []
    for row in rows:
        item = json.loads(row["data"])
        if item.get("status") in ("completed", "failed"):
            result.append(
                {
                    "scan_id": item["id"],
                    "owner_id": row["owner"],
                    "project_id": item["project_id"],
                    "decision": item.get("decision"),
                    "risk_score": item.get("risk_score"),
                    "completed_at": item.get("completed_at"),
                }
            )
    db.audit(user["id"], "admin.reports.read", "reports")
    return result


@router.get("/{collection}")
def resources(
    collection: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user=Depends(platform_admin),
):
    kind = COLLECTIONS.get(collection)
    if not kind:
        raise HTTPException(404, "Collection not found")
    with db.connect() as c:
        rows = c.execute(
            "SELECT owner,data FROM resources WHERE kind=? ORDER BY id LIMIT ? OFFSET ?",
            (kind, limit, offset),
        ).fetchall()
    result = [{**json.loads(r["data"]), "owner_id": r["owner"]} for r in rows]
    db.audit(user["id"], "admin.resources.read", collection)
    return result


@router.get("/{collection}/{ident}")
def detail(collection: str, ident: str, user=Depends(platform_admin)):
    kind = COLLECTIONS.get(collection)
    if not kind:
        raise HTTPException(404, "Collection not found")
    item = resource(kind, ident)
    db.audit(user["id"], "admin.resource.read", ident)
    return item
