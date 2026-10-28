# JavaScript and HTML review checks

Run a new repository or ZIP scan. Old reports keep their original findings. Findings and user/admin reports now show low confidence for heuristic JS review results, and engine tables show the tool and scope used by that scan.

The built-in SAST engine inspects `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, and executable inline scripts in `.html`/`.htm`. It does not execute source, fetch script URLs or open the application. JSON/data scripts and ordinary HTML prose are not treated as executable JavaScript.

## Current rules

- **JS-CLIENT-AUTH / CWE-602 / medium / low confidence:** a permission-named variable (for example allowed, authorized, canAccess, canView, isAdmin or isOwner) uses identity/role properties in inline or browser-looking code. This signals review of the backend boundary; it cannot prove that server authorization is missing. Legitimate UI gating and intentionally vulnerable tutorials can match.
- **JS-DYNAMIC-HTML / CWE-79 / medium / low confidence:** a dynamic expression is assigned to `.innerHTML` or `.outerHTML`. Plain static literals, comments and literal examples are excluded. This identifies a sink, not confirmed attacker-controlled input or exploitable XSS. Sanitized or hardcoded dynamic data may be safe and still needs review.

The user-supplied AccessLab example originally returned zero findings. The updated engine finds the permission decision on line91 and dynamic HTML writes on lines93 and109, producing SAST WARN under the default medium-severity policy. All names/data in that training file are fictional; the findings do not claim a real server was compromised.

## Limits and safe failure

These are bounded review patterns, not a JS/TypeScript AST parser or taint analysis. They do not resolve imports, aliases, computed property names, bundled source maps, framework templates, regex-literal grammar or code inside template interpolations. Inline event attributes and external script URLs are not followed. Named permission patterns are deliberately narrow; arbitrary access-control designs can be missed. A result with no matches is not proof of safe authorization.

The lexical masker walks input once and preserves line offsets. Unterminated literals/comments/scripts and inline-script/result limits mark SAST incomplete/failed, so the scan cannot quietly pass. Existing archive/file limits still apply. No credentials or raw source snippets are added to findings. Severity and confidence are distinct: severity expresses the potential issue class; low confidence means investigation is required.

For real access-control assurance, test authenticated backend routes with separate users and records, ownership mismatches, administrator-only actions and denied roles. Browser-only demo logic cannot establish server behavior. Full Semgrep/CodeQL/SCA and authenticated application testing remain separate integrations.
