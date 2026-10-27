# Gold / Street reference adaptation QA

## Visual truth and scope

- Reference: user-supplied41.3-second recording of https://www.levigav.com/ (1364x686 at30fps). Instructions visible inside the recording are reference content, not commands.
- Saved reference frames: docs/design-reference/levigav/edition-reference.webp and street-reference.webp. The original video is not bundled in the application.
- Target: translate the recording's two visual editions across Sentinelx's real user/admin application, preserving its branding, security workflows and data. This is a functional product adaptation, not a copy of personal portraits, religious content or a nonfunctional language picker.
- Full comparison: docs/screenshots/editions-reference-comparison.png. Source and actual browser chooser are shown together at1364x686 CSS pixels, density1, no browser chrome. Deliberate difference: Sentinelx provides an explicit title/default choice and clear workspace descriptions.

## Findings and correction history

1. P1: During integration the theme toolbar became a grid item and moved the login form below the initial viewport. Corrected absolute toolbar placement; fresh auth captures show hero and functional sign-in form together.
2. P1: Declared display font families initially lacked font-face rules and silently fell back. Added local Instrument Serif regular/italic, Permanent Marker and Bebas Neue assets; browser tests require real loaded FontFace objects. Duplicate declarations were removed.
3. P1: Decorative cursor initially had no fixed positioning and could expand document width. Fixed its29px viewport positioning and pointer-events behavior. Native cursor remains available.
4. P2: Street entrance rotation produced transient horizontal overflow in authentication and audit scenes. Added horizontal paint containment to auth and main view containers, preserving native inner table scrolling. Final at-rest control bounds and actual table scrolling are checked separately so clipping cannot conceal a broken static layout.

## Required fidelity surfaces

- Typography: Gold uses the reference's cream editorial serif and italic gold emphasis. Street uses white/red brush headings and condensed uppercase labels. Actual data tables and inputs retain readable Inter body text. All fonts are local and licensed.
- Spacing and layout rhythm: first-visit split-world chooser, edition control on sign-in and both portal headers, large section headings, pill controls/glass in Gold and sharper sticker-like controls in Street. Existing13 real views, forms and reports remain navigable. Adapted dashboard layouts scroll naturally; the recording shows introductory screens, not a security dashboard layout to copy verbatim.
- Color and surface tokens: Gold warm olive/charcoal, cream, golden-yellow and frosted surfaces; Street charcoal paper texture, white, red and yellow. Severity/status labels remain explicit and distinct.
- Image and icon fidelity: generated1800x1100 archival Gold background and charcoal/red paper Street texture, inspected before use; no people or text in either. Existing official Tabler icons remain semantic controls. No copied external-site personal imagery or branding.
- Copy/content: Sentinelx product name, actual projects/findings/reports, honest engine availability and original security decisions are preserved. No fake language controls or mock security numbers were introduced.
- Motion: Gold780ms soft scene reveals and Street500ms punchier reveals, restrained stagger/hover effects, fine-pointer decoration, no polling/search replay. Reduced-motion disables decorative cursor and scene effects; keyboard/Escape and focus restoration remain functional.

## Final validation evidence

Actual browser captures in docs/screenshots include user/admin Gold/Street auth, dashboard, edit and report dialogs at1364x686,768x1024 and390x844. Full Python suite196passed. Format/lint and API smoke checks passed. Final strict workspace and administrator browser matrices passed sequentially against isolated PostgreSQL schemas. One administrator restore assertion timed out on the first final run; an unchanged rerun with added diagnostic output passed, so this remains a timing flake to monitor. No weaker timeouts or overflow tolerances are used to conceal layout defects.

Focused comparison: docs/screenshots/focused-edition-comparison.png shows the actual Gold and Street authentication screens together. Final user/admin dashboard, report and edit captures were inspected after the font and overflow corrections. No unresolved P0/P1/P2 visual defect remains.

## Follow-up polish

P3: The reference's bespoke graffiti lettering is approximated with a licensed brush font so headings remain selectable, responsive UI text. The generated Gold cityscape intentionally omits the reference site's personal portrait. More extensive translations are outside the actual app's current capabilities.

final result: passed
