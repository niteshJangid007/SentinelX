"""Local operator CLI. Credentials are prompted, never command-line arguments."""

import argparse
import getpass
import sys
import uuid
from pydantic import ValidationError
from . import auth, db, schemas


class AdminSetupError(ValueError):
    """Safe operator-facing error with no submitted credentials."""


def create_admin(email, password=None, grant_existing=False):
    """Bootstrap a platform operator using server-local access, not public API.

    Passing password is supported for local Python automation/tests; the CLI never
    accepts or prints it. Granting an existing account requires an explicit flag
    and retains its password and workspace role.
    """
    email = schemas.Credentials(email=email, password=password or "validation-only-password").email
    db.initialize()
    with db.connect() as c:
        existing = c.execute(
            "SELECT u.id,COALESCE(uc.disabled,0) AS disabled FROM users u LEFT JOIN user_controls uc ON uc.user_id=u.id WHERE u.email=?",
            (email,),
        ).fetchone()
        if existing:
            if not grant_existing:
                raise AdminSetupError(
                    "Account already exists. Use a different email, or explicitly use --grant-existing for your own existing account."
                )
            if existing["disabled"]:
                raise AdminSetupError(
                    "This account is disabled. Re-enable it before granting platform access."
                )
            ident = existing["id"]
        else:
            if grant_existing:
                raise AdminSetupError(
                    "No existing account has this email. Create a new administrator without --grant-existing."
                )
            credentials = schemas.Credentials(email=email, password=password or "")
            ident = str(uuid.uuid4())
            c.execute(
                "INSERT INTO users(id,email,password,role) VALUES(?,?,?,?)",
                (ident, email, auth.password_hash(credentials.password), "admin"),
            )
        c.execute(
            "INSERT INTO platform_admins(user_id) VALUES(?) ON CONFLICT(user_id) DO NOTHING",
            (ident,),
        )
    db.audit(ident, "admin.bootstrap.granted", ident, "local_operator")
    return ident


def main(argv=None):
    parser = argparse.ArgumentParser(description="Sentinelx local operator management")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser(
        "create-admin", help="Create a platform administrator using a hidden password prompt"
    )
    create.add_argument("--email", help="Administrator email (prompted if omitted)")
    create.add_argument(
        "--grant-existing",
        action="store_true",
        help="Grant platform access to a verified existing account; retain its credentials",
    )
    args = parser.parse_args(argv)
    email = args.email or input("Administrator email: ").strip()
    try:
        password = None
        if not args.grant_existing:
            password = getpass.getpass("Administrator password (12+ characters): ")
            if password != getpass.getpass("Confirm administrator password: "):
                raise AdminSetupError("Passwords do not match. Enter the same password twice.")
        create_admin(email, password, grant_existing=args.grant_existing)
    except AdminSetupError as error:
        print(str(error), file=sys.stderr)
        return 1
    except ValidationError as error:
        fields = {item["loc"][0] for item in error.errors() if item["loc"]}
        if "email" in fields:
            print("Enter a valid email address, such as name@example.com.", file=sys.stderr)
        else:
            print(
                "Password must contain between 12 and 256 characters. Its value is not displayed.",
                file=sys.stderr,
            )
        return 1
    except ValueError:
        print("Administrator setup failed. Check the account configuration.", file=sys.stderr)
        return 1
    except db.IntegrityError:
        print(
            "Administrator setup conflicted with an existing account; retry after checking account state.",
            file=sys.stderr,
        )
        return 1
    print("Platform administrator access granted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
