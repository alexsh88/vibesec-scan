# Evaluation

```bash
npm run eval:vuln-app                     # mock mode without ANTHROPIC_API_KEY: hermetic, free
npm run eval:vuln-app -- --budget=5       # live mode (key in .env): real Claude + live OSV/registries
```

## Harness

`apps/api/scripts/evalVulnApp.ts` runs the **real pipeline in-process**. It uses the production composition root (`createContainer`), clones `fixtures/vuln-app` locally through git, and drives the HTTP API via `app.inject`. It then scores the result with `apps/api/scripts/vulnAppScore.ts`.

- **Mock mode:** deterministic LLM responders, with OSV and npm/PyPI served from offline fixtures. Fast and free, and used by the end-to-end test.
- **Live mode:** real Claude calls and live OSV/registries. Cost is bounded by the scan budget (`--budget=<usd>` or `EVAL_BUDGET_USD`).
- **Output:** a per-issue table (found/missed + which analyzer), recall overall and per category, false positives, total findings, cost (USD + tokens per analyzer, from the diagnostics endpoint) and duration. The full JSON report is written to the temp directory, never into the repo. The run always exits 0 (it is a measurement) unless the scan itself fails.

## Ground truth (`fixtures/vuln-app/expected.json`)

The fixture is a small Express + TypeScript API, a few Next.js-style frontend files, and a FastAPI worker. It contains **31 planted issues** across every category and **6 safe look-alikes**:

| Category | Planted | Examples |
|---|---|---|
| SAST | 17 | SQL injection, command injection, path traversal, SSRF, reflected XSS, IDOR, missing authentication, forged-JWT bypass, insecure deserialization, weak crypto, open redirect |
| Taint | 1 | Cross-file source → sink flow |
| Config | 4 | CORS misconfiguration, missing Supabase RLS policy, CI/CD script injection (GitHub Actions), insecure Dockerfile |
| Credentials | 4 | Hardcoded and client-exposed keys |
| Dependencies | 5 | Vulnerable packages with known advisories |

Each issue records file, line (+ tolerance), the expected line content, CWE, a rule hint (+ accepted aliases) and a minimum severity.

## Scoring methodology

- **Found:** some finding is in the same file, within the line tolerance, and *compatible* by one of three tests: same category, same CWE, or a matching rule hint (kebab-normalized containment). A taint finding is accepted for a planted SAST issue. This matters because cross-analyzer dedupe deliberately merges SAST and taint reports of the same bug, and the taint report (which carries the trace) wins.
- **False positive (concern-aware):** a safe look-alike counts as a false positive only when a finding of the **same concern** (same CWE family or rule hint) covers its line.
- **Other findings on safe lines:** listed separately for review. A different-concern finding there may be legitimate, for example missing authentication on the route that contains a safe `path.join`.

## Live results

These were measured by the lead with real Claude on the full pipeline, at default model tiers.

| Run | Scope | Recall | False positives | Cost | Duration | LLM calls |
|---|---|---|---|---|---|---|
| 1 | Analyzers only (milestone P6) | 30/31 | 3/6 (old metric: *any* finding on a safe line) | $0.69 | 139 s | 72 |
| 2 | Analyzers, after fixes | 30/31 | 1/6 same-concern | $0.70 | 128 s | 72 |
| 3 | **Full pipeline**: verify + skeptic, scoring, synthesis | **31/31** | **0/6** same-concern | **$1.19** | **287 s** | **93** |

What changed between runs:
- **Run 1 → 2:**
  - Run 1 produced ~60 quality findings, most of them re-reported injections and hardcoded credentials. The quality analyzer is now constrained to a maintainability-only rule catalogue.
  - Run 1 surfaced a transport bug: the SDK validated structured output itself, so a truncated or off-schema reply became a permanent error with no repair attempt. Fixed for every analyzer.
  - Run 1's "miss" (a Supabase service-role key used in browser code) had in fact been found by SAST under a different rule label. The ground truth now accepts that label, and SAST also receives deterministic client-exposure hints.
  - The false-positive metric was made concern-aware.
- **Run 2's miss:** the Dockerfile `curl | sh` (V23). Claude refuted both deterministic Dockerfile hints, and refuted hints used to be dropped. Now an AI verdict can only downgrade a deterministic hint (to `info`, with its reason); it can never make it disappear.
- **The fixture was wrong, not the scanner.** Run 2's one same-concern "false positive" was on a look-alike redirect guard using `startsWith('/')`. That guard is a **real open redirect**, because `//evil.com` passes. The model was right, and the fixture was fixed.
- **Run 2 → 3:**
  - Verification, skeptic, scoring and synthesis were added.
  - Run 3's only scorer "miss" (`eval` of LLM output, V12) was found as a critical `taint/code-injection` on the exact line: dedupe correctly kept the taint finding over SAST. The scorer was corrected to accept taint findings for planted SAST issues.

## Caveats

- **Small and synthetic:** 31 issues in one app written to be found. Real-world precision will be lower, and recall on unfamiliar frameworks is unmeasured.
- **Single runs:** LLM output is nondeterministic, so a repeated run can differ by an issue or two. These numbers are a regression signal, not a benchmark claim.
- **Live OSV data changes over time**, so the dependency results and their cost drift.
- **Next:** repeated runs with variance, a held-out set of real vulnerable open-source repos (known CVE-fix commits), and per-analyzer precision on unlabelled findings via human review.
