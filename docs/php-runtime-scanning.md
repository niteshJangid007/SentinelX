# PHP runtime advisory checks

Connect a public GitHub repository and run a new scan, or upload a source ZIP. Existing completed reports are immutable snapshots; rescan to use the new checks. Open Findings and filter Critical, or open the scan report and expand the CVE finding. Both user and administrator reports include the same evidence and remediation. The overview includes a PHP runtime gate when PHP evidence exists.

## Supported evidence

- Official `php` Docker base images, including `docker.io/library/php`, in Dockerfile-style files.
- Simple `image:` scalar declarations in Compose/Kubernetes YAML; literal/folded script blocks are excluded.
- `.php-version` declarations.
- `composer.json` or PHP source identifies PHP usage but does not establish the installed runtime. Composer requirements and `config.platform.php` are never treated as deployed versions.

For example, `FROM php:8.3.35-fpm` produces two critical version-match findings: CVE-2026-109618 and CVE-2026-109619. Each includes the file/line, declared version, branch-specific patched version, medium confidence, official source URL and deployment verification guidance. `FROM php:8.3-fpm` produces an informational unknown-version finding and an UNKNOWN gate. An exact patched version has no match in this catalog; this does not certify safety. Missing required SCA/container/DAST coverage still blocks release.

## Catalog and trust boundary

The initial offline catalog was reviewed against these PHP-maintained advisories on 2026-10-28:

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

Both list patched releases 8.2.35, 8.3.36, 8.4.27 and 8.5.12. Matching is numeric within those four branches. Other branches, prerequisites and deployment conditions are not inferred. Catalog changes require source review and regression testing in `app/php_runtime.py`; there is no automatic advisory synchronization or general dependency CVE engine yet. Reports identify the catalog review date.

All input is treated as untrusted text. Scans never execute PHP, resolve shell variables, build/pull images, install dependencies, connect to deployment servers or run exploit requests. Repository content cannot supply a replacement advisory feed. The number of evidence records and findings is bounded; overflow fails the scan closed. Raw image/configuration values are not copied into runtime metadata.

## Limits

Docker multistage declarations are reported as evidence, including build stages that may never be deployed. Custom images, YAML templates/anchors/flow mappings, Docker argument expansion/continuations and installed package-manager PHP versions are not resolved. Image tags are mutable; even digest-bearing declarations are not verified against their image contents. `.php-version` expresses intent, not observed runtime. Exact source-declared versions have medium confidence; authenticated deployed inventory is needed for stronger evidence.

These checks detect two known runtime-version matches. They cannot discover a new PHP memory-corruption bug, confirm exploitability, prove that patching was deployed, or replace SCA/container scanning. Independent configuration review remains necessary. Unknown versions never count as verified safe.
