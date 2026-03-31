# Mesh Infinity Agent Guidelines

## Source of Truth
- `SPEC.md` is the authoritative specification.
- `README.md` files are for end users only and must not override `SPEC.md`.

## UI Direction
- The Flutter UI (`frontend/`) is the canonical UI across platforms.
- The Slint UI is deprecated and should only be referenced for parity checks.
- The SwiftUI app (`MeshInfinity/`) is deprecated and should only be referenced for parity checks.

## Platform Scope
- All platforms are in scope for this phase.
- Android is the primary focus; iOS is incidental (do not prioritize iOS-specific work).

## Implementation Principles
- Keep platform-specific code minimal; prefer shared Rust + Flutter logic.
- Align behavior with `SPEC.md` even if existing code or docs diverge.
- Cloud services are prohibited for all platforms (no Google Play services, Apple cloud services, or Microsoft cloud services).
- **No stubs, shims, placeholders, or non-functional code.** When a feature requires backend support that does not yet exist, implement it. Do not add fake or no-op implementations unless the user explicitly permits it for a specific case.


## Security Audit Protocol

When an agent (Claude, Codex, or other) discovers a security vulnerability or spec inconsistency during review:

1. **Before resolution:** Write the finding to `.audits/<agent>-unresolved/YYYY-MM-DD-<slug>.md` (one file per finding). Use `.audits/claude-unresolved/` for Claude, `.audits/codex-unresolved/` for Codex, etc. Each agent directory is a folder — create it if it doesn't exist.
2. **After resolution** (fix verified and landed): Move the file to `.audits/resolved/` (a flat folder) and update its status header to `RESOLVED`.
3. **Format:**
   ```markdown
   # <Title>
   **Date:** YYYY-MM-DD
   **Auditor:** <agent-name>
   **Status:** UNRESOLVED | RESOLVED
   **Severity:** High | Medium | Low

   ## Issue
   <what the problem is, with file:line references>

   ## Resolution  (fill in when resolved)
   <what was changed and where>
   ```
4. Findings must be verified before filing — do not file speculative issues without reading the relevant spec/code sections.
5. A finding is resolved only when the fix is in `SPEC.md` or the codebase, not merely when a fix is proposed.

## LLM and Gitignore Rules

- Files matched by `.gitignore`, and files inside folders or subfolders matched by `.gitignore`, must never be committed or pushed.
- If such files were committed, they must be removed from the index and from published history before further pushes.
- LLMs must not create commits that include gitignored files or files under gitignored directory trees.
- LLMs must not treat `.gitignore` as advisory. It is a hard boundary for repository contents.

## Compliant Code Standards (Minimum)

These are the minimum standards code must meet to be considered **compliant**. Compliant code satisfies all three of: (1) these standards, (2) adherence to `SPEC.md`, and (3) accuracy as determined by human review.

Apply these as the **standard code-review set** on every review pass:

1. **Are any warnings or errors being suppressed?** This is an illegal operation — warnings and errors need to be treated as valid and fixed without being hidden.

2. **Are any tests failing to represent the threat model?** If so, those tests need to be improved.

3. **Does every file in the repo pass the end-user/contributor test?** Each committed file must be something an end user needs to build the project, or a human contributor needs to make a contribution. Files that fail this test belong in `.gitignore`.

4. **Do any commits reference an LLM beyond attributing a specific finding?** Commit messages describe the code change and the developer is the author. The only permitted LLM reference is crediting a specific discovery: `"finding surfaced by review from <name>"`.

5. **Do any functions, systems, or code have multiple implementations, unused implementation, multiple typedefs, unnecessary imports, etc?** We reuse and improve existing code whenever possible.

6. **Are any functions, systems, or things in the specification currently unimplemented?** This needs to be corrected.

7. **Are there any potential vulnerabilities in the code or the spec?** Vulnerabilities must be evaluated from two distinct threat perspectives: (a) a **malicious attacker** following our threat model, and (b) **the stupidest user we can imagine** — someone who will click the wrong button, send the wrong input, or use the app in ways no sane person would. Both perspectives are equally important for producing a secure and robust application. Any found vulnerabilities must be raised to the appropriate party. AI Agents raise findings and proposed solutions to the user, who determines how to proceed, but must also provide one or more proposed solutions or references to reinforce the finding.

8. **Does code follow the project conventions?** This project uses snake_case.

9. **Does the code properly error-handle?** It needs to.

10. **Is the code implemented in a way that is simple and easy to read?** It needs to be.

11. **Is the code sufficiently commented?** On average, every line of code should have two lines of comments. This commentspace exists to maximize understanding — use it liberally to explain intent, context, and reasoning, not to fill a quota.
