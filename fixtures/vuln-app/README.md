# vuln-app

A small, intentionally vulnerable sample application used as a fixture for VibeSec's scanner
tests and evals: an Express + TypeScript API, a few Next.js-style frontend files, and a small
Python FastAPI worker.

**This app is intentionally vulnerable. Do not deploy it anywhere, and do not reuse its code.**

It contains deliberately planted SQL injection, command injection, path traversal, SSRF,
reflected XSS, IDOR, missing authentication, a forged-JWT bypass, insecure deserialization,
hardcoded and client-exposed credentials, weak crypto, an open redirect, a CORS
misconfiguration, a missing Supabase RLS policy, a CI/CD script-injection path, and an insecure
Dockerfile — alongside a few safe look-alikes used to measure false positives.

See `expected.json` for the ground-truth list of planted issues.
