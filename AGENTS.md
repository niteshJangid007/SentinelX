# Sentinelx development rules

Use the existing checkout. Do not create a worktree unless requested.

## Required feature workflow

1. Define acceptance criteria, trust boundaries, abuse cases, and authorization requirements.
2. Use TDD: write a meaningful failing unit or integration test, run it and capture the actual failure, then implement the smallest change that passes. Refactor with tests green. Never claim existing code was written test-first retroactively.
3. Add integration tests across the actual API, temporary database, scanner, policy, and reports where affected. Mock external network boundaries only; include real local scanner integration for scan changes.
4. Before declaring each feature complete, run adversarial tests of it and neighboring authorization boundaries. Use this application, temporary databases and synthetic fixtures only. Do not attack connected repositories, infrastructure or live applications without explicit scope authorization. Source inspection is separate from penetration testing.
5. Record red/green commands, outcomes, attack cases, fixes, and remaining limitations in the feature PR or docs/testing.md. Add regression coverage for discovered defects.
6. Run `bash scripts/check.sh` before completion. Never substitute a zero-test run, skip checks silently, expose secret evidence, or label a limited regression suite a comprehensive penetration assessment.

Tests use pytest marks: unit, integration, security. Tests must exercise behavior and plausible regressions, not mirror implementation. Authentication credentials in tests must be synthetic. No production data or targets.

Run one API worker. Missing security-engine coverage must block release approval. Do not execute untrusted repository source, hooks or Dockerfiles in this API process.
