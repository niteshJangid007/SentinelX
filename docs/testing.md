# Testing and feature completion

Run `bash scripts/check.sh` from the checkout after installing requirements.lock into .venv. CI uses the same script with PYTHON_BIN=python. It runs separate unit, integration and security suites, writes JUnit XML in ignored test-results/, and starts a real HTTP server against a temporary database for a vulnerable ZIP scan-to-report smoke test. The server and temporary database are cleaned up automatically. Tests use synthetic credentials, malicious archive fixtures, and temporary databases. No public services are attacked.

## Current Gold / Street validation

The current full Python suite has **196 passing tests** against live PostgreSQL, with no skipped tests and one upstream Starlette/AnyIO deprecation warning. This supersedes the historical counts below. Ruff formatting/correctness lint, JavaScript syntax, and `bash scripts/check.sh` passed, including the real HTTP scan/report smoke test.

The redesign preserves real backend workflows. Browser acceptance checks both Gold and Street across all seven workspace views and six administrator views at desktop1364x686, tablet768x1024 and mobile390x844. Checks include actual loaded local fonts, keyboard edition selection, remembered preference, reduced motion, scene stability during refresh/filter, entrance overflow, resting control bounds and horizontal table scrolling. Actual CRUD, ZIP scan/report download, hostile-name escaping, HttpOnly sessions and reload/logout behavior remain covered. Final visual evidence is recorded in `design-qa.md`.

A test-isolation defect was corrected before validation: an autouse fixture clears inherited database/production configuration and selects disposable SQLite by default; explicit PostgreSQL tests use their own generated schemas. Regression checks prove a disposable PostgreSQL sentinel survives nested pytest and that HTTP smoke ignores an inherited database URL. These fixes prevent ordinary test runs from modifying configured application data. They do not change runtime database configuration.

## TDD contract

New features and fixes start with failing behavior tests, followed by implementation and green tests, then refactoring. Feature completion requires unit tests, relevant integration tests, adversarial verification, and recorded evidence. Existing tests added after implementation are regression/characterization coverage; the initial backend was not developed entirely test-first. Repository AGENTS.md carries these requirements into future work.

## Coverage

- Unit: password hashing, session storage/expiry, role checks, schema constraints, database persistence and isolation, archive bounds, URL validation, heuristic scanner rules and policy decisions.
- Integration: authenticated API workflows; real ZIP ingestion through scanners, persistence, findings, reports, audit and deployment gates; restart recovery and ownership boundaries. External GitHub calls are mocked in deterministic API contract tests; local ZIP integrations do not mock scanners.
- Adversarial: role injection, invalid/injected bearer tokens, expired/revoked sessions, object authorization, SSRF URL/ref variants, traversal, symlinks, corrupt/oversized ZIPs, secret redaction, malformed gate results and missing coverage. Authentication brute-force protection adds direct peer, spoofed forwarding header, threshold, expiry and bounded state checks.
- HTTP smoke: live Uvicorn, health, registration, project creation, actual vulnerable ZIP scan, findings, blocked release and report generation.

These are focused automated security checks, not a comprehensive independent penetration assessment. There is no permission to attack arbitrary applications, GitHub accounts, network infrastructure or production services. Any future live-target penetration work needs explicit authorized target and scope.

## Authentication throttle feature: TDD evidence

The security agent ran `tests/test_auth_throttle.py` before implementation: eight tests failed because auth requests were not throttled and the limiter was absent. Implementation then adds an in-memory per-peer sliding window shared by login and registration, bounded capacity, Retry-After, thread safety and injectable monotonic time. Regression tests cover blocked attempts, recovery after expiry, peer isolation and ignoring spoofed forwarding headers.

Uvicorn must use `--no-proxy-headers` for the direct/local deployment. Otherwise a trusted local reverse proxy could cause forwarding headers to rewrite Request.client before application checks. When adding ingress, design and test trusted-proxy handling deliberately. A peer-based limit can also group legitimate users behind NAT. The in-memory throttle is one-process mitigation; it resets on restart and is not a shared multi-instance rate limiter. Public production deployment still needs ingress controls and distributed abuse protection.

## Latest local verification

The full suite contains 100 distinct passing tests. `bash scripts/check.sh` also passed all stages: 70 unit selections, 21 integration selections, and 17 security selections, followed by the real HTTP scan/report smoke test. Some authentication tests carry two markers, so stage counts overlap. JUnit files are produced in test-results/. One upstream Starlette/AnyIO deprecation warning remains; it is not a failed or skipped test. CI is configured to run this workflow, but remote GitHub Actions execution has not been claimed.

## Windows ZIP filename regression

A Windows run reported one failed backslash-path test. Reproduced test-first using Windows separator behavior: the fixture writer and ZIP reader normalize backslashes. Updated fixtures to preserve original malicious names and scanner validation to reject backslashes/NUL in ZipInfo.orig_filename before normalization. The new regression failed before the scanner fix and passed after. Validation is performed on Linux with simulated Windows ZIP separator behavior; native Windows rerun remains required.

## Dashboard acceptance testing

The dashboard hosting feature began with missing-homepage/static-host tests, then passed after implementation. A real-browser test also failed against the running server while app.js was absent: clicking account creation could not activate registration. Browser acceptance uses the same API and real scanner with a synthetic vulnerable ZIP, not fake scan data. It exercises authentication, project/repository connection, report rendering and JSON download, XSS escaping, memory-only tokens and mobile layout. `scripts/browser_test.py` requires `requirements-browser.txt`, Playwright Chromium, and a running API at SECUREFLOW_TEST_BASE_URL (defaults to port8001). Set BROWSER_EXECUTABLE only to use a system Chromium. The optional SECUREFLOW_TEST_GITHUB=1 mode exercises a real public GitHub source fetch; CI uses local ZIP fixtures for deterministic scans.

Windows dashboard: extract the update into the project folder, stop an old server, double-click Start-Sentinelx.cmd and open the root app address. No Node installation or separate frontend service is required.

Dashboard validation completed: 105 distinct Python tests passed; categorized unit/integration/security checks and HTTP smoke passed. The full browser run with SECUREFLOW_TEST_GITHUB=1 passed real GitHub connect → source scan → report download, actual ZIP findings/report, hostile-name XSS handling, in-memory auth storage checks, and mobile390px navigation without page overflow. No JavaScript errors occurred. Native Windows browser testing was not performed here; the launcher uses the already-verified Python backend and platform-neutral static assets.

Sentinelx rename: added branding regression first (failed on API title), then updated browser/API/scanner/report branding and launcher. All106 Python tests and check.sh passed. Existing database and configuration keys are retained for compatibility.

## Administrator portal and PostgreSQL

Admin API TDD: eight initial feature failures preceded the implementation; the expanded administrator suite contains 20 passing tests. PostgreSQL adapter and migration validation were also test-first (missing adapter/module or target behavior initially failed). Public workspace admin roles never grant platform membership. Bootstrap is a local hidden-password CLI, with no shared default credentials.

Latest full suite:134 passed with TEST_DATABASE_URL pointing at a live local PostgreSQL16 service, zero skipped. This includes isolated PostgreSQL schema CRUD, rollback/constraint handling, API authentication, and SQLite-to-PostgreSQL migration preserving password hashes and ownership while leaving source untouched. A nonempty import target is rejected and sessions are intentionally not imported. check.sh passed76 unit,52 integration and40 security selections (overlapping markers) and actual HTTP smoke.

Both workspace browser tests (including real public GitHub download/scan/report) and admin browser tests passed against PostgreSQL. Admin browser checks cover unauthorized/member rejection, separate admin login, cross-account review, disabled session revocation, enable/role changes, viewer permissions, real source report downloads, XSS, audit logging, mobile layout and memory-only tokens. `scripts/check_admin_browser.py` runs these in a generated temporary PostgreSQL schema, bootstraps a synthetic administrator in-process without printing credentials, starts/stops an isolated API, and drops only that schema afterwards. CI now provisions PostgreSQL for these checks. Remote CI execution and native Windows PostgreSQL launcher execution have not been claimed.

## Persistent dashboards, severity and deployment update

160 distinct tests passed with live PostgreSQL integration. Persistent user and admin HttpOnly cookie tests began red and passed after implementation; CSRF, separate logout and cookie attributes are checked. PostgreSQL records were confirmed intact before session fixes. Browser suites against isolated PostgreSQL schemas verified reload and fresh browser-context restoration, actual severity chart counts and accessibility labels, mobile navigation/logout and denied sessions after logout. Mobile sign-out visibility was found failing and fixed. Production refuses missing database configuration instead of silently choosing SQLite; external .env DATABASE_URL selection is tested. Deployment YAML/Compose and Caddy configuration validated; no external publication performed.

## Approved Option 3 theme

Visual source: docs/design-reference/option-3.png, selected by user after three generated previews. Browser TDD first failed on the absent new overview heading. Mobile browser tests then exposed horizontal overflow during the shell/CSS integration; grid/header constraints fixed it. Final automated checks cover the compact navigation, inline metrics, severity strip, repository activity/release summary/engine execution regions, real scanning/report downloads, session restoration, all mobile tabs, logout and asset/CSP errors. Desktop screenshots use1440x1024 with actual saved fixture scans; display numbers intentionally differ from illustrative source data. All160 Python tests and check.sh passed. Official Tabler icons and Inter fonts are vendored with licenses and package integrity checks, with no external font/icon runtime requests. No database or authentication migration is needed for this theme update.

## Mixed old/new assets repair

A Windows screenshot showed the new HTML shell alongside the old green stylesheet and old dashboard JavaScript. Added a failing regression proving unversioned asset URLs, then updated HTML rendering to compute SHA-256 content fingerprints for each CSS/JS URL and mark all frontend assets no-store. Static HTML also carries an explicit option3-r2 fallback version for compatibility with a still-running older backend. Browser acceptance now asserts versioned requests, no-store asset responses, an80px desktop rail and the actual computed blue primary action color. The patch bundles the complete matching static asset set, not only the HTML shell.

## Final CRUD/source delivery

Added project/repository server-side Create, Read, Update, Delete and Search routes in app/projects.py with reusable validation, explicit confirmations, active-scan protection, owner-scoped transactional cascades, rollback on audit failure, and a shared single-worker mutation lock with source revalidation before queue admission. API CRUD TDD started4red; safe database handlers started6red. Browser CRUD first failed on the absent management row and now passes actual PostgreSQL create/read/edit/search/disconnect/delete with no leftovers, retaining real scanning/report/security/reload/mobile checks. Admin browser regression passed.

Final full suite:186 passed with live PostgreSQL and no skipped tests. Ruff formatting and selected correctness lint pass for all Python modules/scripts/tests; JavaScript syntax checks pass. The source publication excludes .env credentials, runtime databases, caches and test-result files. Database errors return structured generic409/503/500 responses with safe logs instead of SQL/credential details.

## Local PostgreSQL password mismatch repair

Repair TDD began with8missing-module failures, then8unit tests passed (11including launcher settings). Formatting and correctness lint pass. A real isolated PostgreSQL16 container was initialized with one password and a saved preservation record, then its local .env was changed to another password. TCP authentication failure was reproduced; the local repair synchronized the role password and the original record was verified unchanged. The temporary test container alone was removed. An additional idempotent repair against the existing development database preserved user/resource/platform-admin counts. Real credentials never appeared in arguments or tool output. External URLs, production flags and unsafe missing configuration are rejected. No database volumes or application passwords are changed by the repair helper.

## PHP runtime advisory matching (2026-10-28)

Acceptance: recognize pinned official PHP image/runtime declarations, compare only the four catalogued branches numerically, preserve unknown version status for floating/dynamic values and Composer constraints, and expose CVE evidence and branch-specific upgrade guidance through the real scan/report workflow. No repository execution, image pulls, shell expansion, live exploit requests or user-controlled advisory sources are allowed.

TDD started with `pytest tests/test_php_runtime.py -q`: 18 failures and one existing-behavior pass before implementation. Follow-up adversarial tests exposed unbounded repeated evidence and an UNKNOWN gate that could pass policy evaluation; both failed before fixes and now pass. Coverage includes all four patch boundaries, later patch versions, prereleases, unsupported branches, comments, custom registries, dynamic shell text, malformed Composer data and resource exhaustion. A real API upload/persistence/report test verifies both CVEs survive saving, remediation is preserved, and another account cannot read the report.

Full suite with live isolated PostgreSQL: **224 passed**, no skipped tests, one upstream Starlette/AnyIO deprecation warning. This supersedes historical counts above. The PHP catalog is a reviewed two-advisory snapshot, not automatic security intelligence. See `docs/php-runtime-scanning.md` for evidence and scope limits.

Independent adversarial review also found YAML block-scalar script text being misclassified as a deployment image and a warning-policy inconsistency in UNKNOWN presentation. Four scalar regressions and one policy regression failed first; scalar-context skipping and gate precedence fixed them. A dedent regression preserves detection of a real image after a script block. The PostgreSQL-backed browser suite passed actual PHP ZIP scanning, both CVEs rendered in the report, JSON metadata, all Gold/Street viewports, CRUD/security/session checks and zero JavaScript errors. GitHub transport was not exercised in this run; it shares the same archive analysis path.

Final `bash scripts/check.sh` with live isolated PostgreSQL passed 124 unit, 98 integration and 81 security selections (markers overlap), zero skipped, plus the real HTTP ZIP-to-report smoke. Formatting, correctness lint and JavaScript syntax checks passed.

## JavaScript / inline HTML SAST review rules

The AccessLab upload reproduced zero findings before this feature. TDD added behavior tests for inline authorization predicates, dynamic HTML assignments, exact line locations, standalone scripts, static literals, comments, JSON script blocks and malformed/unclosed scripts: four initial tests failed while seven baseline negative/safety behaviors passed. The source checks now detect the actual supplied file at lines91,93,109 as medium-severity, low-confidence review signals; they do not claim an exploitable backend authorization bypass or confirmed XSS.

A regression first exposed server-only Node permission logic being labelled client-side; authorization patterns now require inline/browser context. An independent read-only adversarial review found quadratic regex masking for escaped unterminated strings and repeated browser-context searches. The masker was replaced with a deterministic forward pass, incomplete lexical state fails SAST, and browser-context searches are hoisted. A subsequent modest60KB escaped-string fixture completed in0.0073seconds; no large denial-of-service payloads or live systems were targeted. Additional tests cover inline-script bounds and HTML self-closing/duplicate-type semantics. The reviewer confirmed the fixes and no blocking issue remained. Source is never executed or echoed into finding snippets.

Real API upload integration verifies both rule IDs, confidence, review-required assessment, file/line evidence, persisted findings and SAST WARN in the saved report. Full suite: **241 passed**, no skipped tests with live isolated PostgreSQL. Categorized check.sh stages passed140 unit,99 integration,84 security selections (overlapping markers), plus real HTTP smoke. Post-review lexer/matching optimizations also passed all16 JS-focused tests. Ruff formatting/correctness and JavaScript syntax are checked before delivery. See `docs/javascript-scanning.md` for supported patterns and explicit limitations.

Final PostgreSQL-backed user and administrator browser suites passed sequentially. They verify persisted JS rule IDs, rendered low-confidence labels in expanded report findings, JSON downloads, the engine scope columns, all Gold/Street desktop/tablet/mobile layouts, CRUD/account controls, XSS escaping and session restoration/logout. No JavaScript errors occurred. Browser confidence assertions were scoped to the expanded finding after an initial selector chose a collapsed sibling. No public GitHub source fetch was exercised in this run; repository and ZIP scans share the archive-analysis path.
