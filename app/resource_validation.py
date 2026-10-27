"""Reusable validation and owner-scoped resource access for API routers."""

from functools import wraps
from threading import RLock
from fastapi import HTTPException
from . import db, scanner


def nonblank(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("A nonblank value is required")
    if any(ord(char) < 32 for char in value):
        raise ValueError("Control characters are not allowed")
    return value


def repository_url(value: str) -> str:
    return scanner.validate_repository_url(value)


def repository_branch(value: str) -> str:
    return scanner.validate_branch(value)


def owned(kind: str, owner: str, ident: str) -> dict:
    item = db.get(kind, owner, ident)
    if item is None:
        raise HTTPException(404, "Resource not found")
    return item


# The application runs one API worker. Serialize related resource mutations and
# queue admission so deletion cannot race a stale scan-source lookup.
mutation_lock = RLock()


def serialized_mutation(function):
    @wraps(function)
    def locked(*args, **kwargs):
        with mutation_lock:
            return function(*args, **kwargs)

    return locked
