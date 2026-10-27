"""Owner-scoped project and repository CRUD with explicit deletion safeguards."""

import json
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from . import auth, db, schemas
from .resource_validation import owned, serialized_mutation

router = APIRouter(prefix="/api/v1", tags=["Projects and repositories"])


def searched(kind, owner, q, limit, offset):
    query = q.strip().casefold()
    fields = (
        ("name", "description", "technology", "environment")
        if kind == "project"
        else ("url", "branch", "provider")
    )
    items = db.listing(kind, owner)
    return [
        item
        for item in items
        if not query or any(query in str(item.get(field, "")).casefold() for field in fields)
    ][offset : offset + limit]


@router.post("/projects", status_code=201)
@serialized_mutation
def create_project(body: schemas.Project, user=Depends(auth.writer)):
    item = db.create("project", user["id"], body.model_dump())
    db.audit(user["id"], "project.created", item["id"])
    return item


@router.get("/projects")
def projects(
    q: str = Query("", max_length=300),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user=Depends(auth.current_user),
):
    return searched("project", user["id"], q, limit, offset)


@router.get("/projects/{ident}")
def project(ident: str, user=Depends(auth.current_user)):
    return owned("project", user["id"], ident)


@router.put("/projects/{ident}")
@serialized_mutation
def update_project(ident: str, body: schemas.Project, user=Depends(auth.writer)):
    owned("project", user["id"], ident)
    item = db.update("project", user["id"], ident, body.model_dump())
    db.audit(user["id"], "project.updated", ident)
    return item


@router.post("/repositories", status_code=201)
@serialized_mutation
def connect_repository(body: schemas.Repository, user=Depends(auth.writer)):
    owned("project", user["id"], body.project_id)
    item = db.create(
        "repository",
        user["id"],
        {
            **body.model_dump(),
            "provider": "github",
            "connection": "configured",
            "authentication": "public-or-server-bound",
        },
    )
    db.audit(user["id"], "repository.connected", item["id"])
    return item


@router.get("/repositories")
def repositories(
    q: str = Query("", max_length=300),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user=Depends(auth.current_user),
):
    return searched("repository", user["id"], q, limit, offset)


@router.get("/repositories/{ident}")
def repository(ident: str, user=Depends(auth.current_user)):
    return owned("repository", user["id"], ident)


@router.put("/repositories/{ident}")
@serialized_mutation
def update_repository(ident: str, body: schemas.Repository, user=Depends(auth.writer)):
    owned("repository", user["id"], ident)
    owned("project", user["id"], body.project_id)
    item = db.update("repository", user["id"], ident, body.model_dump())
    db.audit(user["id"], "repository.updated", ident)
    return item


@serialized_mutation
def delete_owned(kind, owner, ident, confirm):
    if not confirm:
        raise HTTPException(400, "Explicit confirmation is required")
    # Read and delete every affected row in a single transaction. Audit history
    # remains intact and the deletion event commits atomically with the cascade.
    with db.connect() as connection:
        if isinstance(connection, db.Connection):
            connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            "SELECT id,kind,data FROM resources WHERE owner=?", (owner,)
        ).fetchall()
        records = [(row["kind"], json.loads(row["data"])) for row in rows]
        target = next(
            (item for item_kind, item in records if item_kind == kind and item["id"] == ident), None
        )
        if target is None:
            raise HTTPException(404, "Resource not found")
        scans = [
            item
            for item_kind, item in records
            if item_kind == "scan"
            and item.get("project_id" if kind == "project" else "repository_id") == ident
        ]
        if any(item.get("status") in ("queued", "running") for item in scans):
            raise HTTPException(
                409, "Wait for active scans to finish before deleting this resource"
            )
        identifiers = {ident}
        if kind == "project":
            scan_ids = {item["id"] for item in scans}
            for item_kind, item in records:
                if item_kind in (
                    "repository",
                    "scan",
                    "finding",
                    "deployment",
                    "report",
                    "notification",
                ) and (item.get("project_id") == ident or item.get("scan_id") in scan_ids):
                    identifiers.add(item["id"])
        for resource_id in identifiers:
            connection.execute("DELETE FROM resources WHERE owner=? AND id=?", (owner, resource_id))
        timestamp = db.now()
        audit = {
            "id": str(uuid.uuid4()),
            "created_at": timestamp,
            "updated_at": timestamp,
            "action": kind + ".deleted",
            "resource": ident,
            "result": "success",
            "deleted_resources": len(identifiers),
        }
        connection.execute(
            "INSERT INTO resources VALUES(?,?,?,?)",
            (audit["id"], "audit", owner, json.dumps(audit)),
        )


@router.delete("/projects/{ident}", status_code=204)
def delete_project(ident: str, confirm: bool = Query(...), user=Depends(auth.writer)):
    delete_owned("project", user["id"], ident, confirm)
    return Response(status_code=204)


@router.delete("/repositories/{ident}", status_code=204)
def delete_repository(ident: str, confirm: bool = Query(...), user=Depends(auth.writer)):
    delete_owned("repository", user["id"], ident, confirm)
    return Response(status_code=204)
