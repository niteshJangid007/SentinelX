"""Safe HTTP boundaries for database failures.

Driver messages can contain SQL, submitted values, connection usernames and DSNs.
Never put those messages or exception tracebacks in responses or routine logs.
Handlers cover database exceptions only; application bugs remain visible to the
normal exception machinery and test runner.
"""

import logging
import sqlite3
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from . import db

logger = logging.getLogger("sentinelx.database")

INTEGRITY = db.IntegrityError
UNAVAILABLE = (sqlite3.OperationalError, sqlite3.InterfaceError)
DATABASE_ERRORS = (sqlite3.Error,)
if db.psycopg is not None:
    UNAVAILABLE += (db.psycopg.OperationalError, db.psycopg.InterfaceError)
    DATABASE_ERRORS += (db.psycopg.Error,)


async def database_error_handler(request: Request, error: Exception):
    headers = {"Cache-Control": "no-store"}
    if isinstance(error, INTEGRITY):
        status, code, detail = (
            409,
            "database_conflict",
            "The operation conflicts with existing data.",
        )
    elif isinstance(error, UNAVAILABLE):
        status, code, detail = (
            503,
            "database_unavailable",
            "The database is temporarily unavailable. Try again later.",
        )
        headers["Retry-After"] = "5"
    else:
        status, code, detail = (
            500,
            "database_error",
            "The database operation could not be completed.",
        )
    # Do not include error, repr(error), request URLs or exc_info here.
    logger.warning("database_request_failed class=%s status=%s", type(error).__name__, status)
    return JSONResponse(
        status_code=status, content={"detail": detail, "error": {"code": code}}, headers=headers
    )


def install_error_handlers(app: FastAPI):
    """Install once before serving requests; optional PostgreSQL support is kept."""
    for exception_type in DATABASE_ERRORS:
        app.add_exception_handler(exception_type, database_error_handler)
