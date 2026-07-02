# Red-Team Report — KnoSky v0.5.0

*Adversarial security pass conducted as part of SAT-437 / EPIC-Q pre-pilot hardening.*

---

## What was tested

KnoSky is a local-first tool: it runs entirely on your machine, indexes your folder, and produces a self-contained HTML/JSON artifact. The adversarial surface that matters is the **generated artifact** (city HTML / `city-data.json`), the **indexer** (what it reads, what it refuses, what it puts in the output), and the **local trust root** (key store, ledger, freshness guards). There is no hosted backend.

The pass was structured around four threat categories:

| Category | Scope |
|---|---|
| Indexer / artifact safety | Hostile repo contents — secret leakage, symlink escapes, injection, ignore rules |
| Local trust root | Key-store quorum, revocation, ledger high-water-mark, freshness guards |
| Rendering engine | Large / adversarial repos, subgraph isolation, XSS, postMessage bridge |
| Protocol / schema | Policy fuzzing, route engine, bundle manifest, clock/ledger manipulation |

---

## Findings summary

### Fixed before publication

Three vulnerabilities found during the adversarial pass were fixed before the 0.5.0 release:

**F-001 — Symlink-escape read in the bundle engine.**
`kcBundle` followed symlinks outside the declared root and hashed the outside file as if it were
inside-root content, marking the manifest `clean`. Fixed: symlinks are now blocked at the
bundle layer with `status: "blocked"`, never read, never hashed.
*Regression proof:* `test/redteam-fixtures.mjs` (scenario 9, regression a).

**F-002 — Unreadable file fail-open in the bundle engine.**
An unreadable file (mode 000) was reported as `clean` rather than blocking the build.
Fixed: `kcBundle` now treats any unreadable file as `status: "blocked"`.
*Regression proof:* `test/redteam-fixtures.mjs` (scenario 9, regression b).

**F-003 — Git-ref option-injection in the CI report generator.**
A git `base` ref shaped like a CLI flag (e.g. `--output=/tmp/evil`) was passed to `git diff`
without sanitization. Fixed: `knoskyCi` now uses `execFileSync` with an explicit args array
instead of a shell string, eliminating the injection surface.
*Regression proof:* `test/redteam-fixtures.mjs` (scenario 10, regression c).

**F-004 — Large-integer ledger lockout (latent DoS, fixed proactively).**
`Number.isInteger(1e100)` evaluates to `true`, so `checkAndAdvance(1e100)` would have
permanently advanced the high-water-mark past any real commit count, preventing any future
artifact from being accepted. Fixed: both `extractLedgerSeq` (structural layer) and
`checkAndAdvance` (persisted guard) now reject values above `MAX_PLAUSIBLE_LEDGER_SEQ`
(1 × 10⁹). This was latent — no inbound/external call path was wired to the HWM yet — and
was fixed proactively before any consumption path was added.
*Regression proof:* `test/trust-root-adversarial.test.mjs` (TR-006).

**F-005 — Secret scan ran after scrubbing, not before.**
The indexer scrubbed PII/secrets from projections before running the secret scan, so a secret
in a heading or summary was silently redacted rather than blocking the build. Fixed: the scan
now runs on un-scrubbed projections; detection blocks the build.
*Regression proof:* `test/security-fixtures.mjs` (scenario 1).

**F-006 — postMessage bridge fail-open.**
The origin-guard condition was structured such that an empty `KC_OK` allowlist disabled the
guard (the `||` short-circuit opened the bridge to all origins instead of closing it).
Fixed: an empty allowlist now completely disables the bridge; the readiness message is never
broadcast to `"*"`.
*Regression proof:* `test/security-fixtures.mjs` (scenario 5).

**F-007 — Malicious-id node could reach route output.**
A node whose `provenance.ref` failed the safety check fell back to its raw `id` in an
`||`-branch inside `kcRoute`, allowing a traversal-shaped id (`../../etc/passwd`) to appear
in route results rather than being excluded.
Fixed: nodes with unsafe fallback ids are excluded from `route[]`; `kcRoute` does not throw.
*Regression proof:* `test/redteam-fixtures.mjs` (scenario 11, regression route-filter).

---

### Accepted limitations (known boundaries, not defects)

The following findings were investigated, classified as accepted design decisions, and
**documented publicly** rather than fixed. Each has a dedicated test that pins the current
behaviour and guards against regression to something *worse*.

**D-163 / RT-KS-001 — N=2 key-store quorum degenerate case.**
When a key store holds exactly 2 non-revoked keys, the quorum formula
(`Math.floor(peers/2)+1`) reduces to 1: the sole peer key alone can revoke the other.
This is mathematically unavoidable at N=2.
*Classification:* accepted limitation. *Mitigation:* maintain N≥3 non-revoked keys for real
threshold protection. *Regression proof:* `test/key-store-quorum-redteam.mjs` (RT-KS-001-A
through RT-KS-001-J). Also confirmed: zero approvals still fail (RT-KS-001-B), forged tokens
still fail (RT-KS-001-C), duplicate-signer dedup is correct (RT-KS-001-D), and N=3 real
threshold is unaffected (RT-KS-001-E through RT-KS-001-I).

**D-167 / RT-KS-002 — M=0 sole-key self-revocation.**
When all peers have been legitimately revoked and exactly 1 non-revoked key remains,
`revokeKey()` requires zero approvals (`required = 0`). This is a **self-wipe**, not a
third-party bypass: requiring an approval that cannot structurally exist would make a
compromised last key permanently irrevocable, which is a worse outcome.
*Classification:* intentional design. *Caller-identity note:* `revokeKey()` currently
authorizes by state (M=0), not caller identity. Tracked for architectural resolution as
SAT-478. `revokeKey` has zero production call sites (enforced by an automated whole-repo
code scan in `test/key-store-quorum-redteam.mjs`).
*Regression proof:* `test/key-store-quorum-redteam.mjs` (RT-KS-002-A through RT-KS-002-D).

**D-168 / SAT-476 — HWM-file deletion or modification.**
An attacker who can delete or modify `ledger.hwm.json` could reset the high-water-mark guard.
*Classification:* same trust boundary as the entire local install (D-164). An attacker with
local filesystem write access already controls KnoSky's code itself; a hardware or remote
anchor would be required to defend against this, which is incompatible with KnoSky's
no-egress principle.
*Regression proof:* `test/ledger.test.mjs` (section k, D-168).

---

### Scenarios with no finding

The following areas were probed with no actionable finding:

| Area | Scenarios covered |
|---|---|
| Indexer hostile inputs | Symlink loops (13 scenarios); huge files (≥8 MB); 2500-file cap enforcement; binary/NUL files; unicode + control-char filenames; garbage `--max` values; cyclic import graphs |
| Secret/PII scanning | Secret in heading/summary blocks build; `--allow-leaks` override; `.gitignore`/`.kcignore` rules; path-traversal in ids; email addresses scrubbed from projections |
| Rendering | `</script>` and U+2028/U+2029 injection; large/streaming repos (600 and 1200 nodes); empty/minimal cities; cross-repo subgraph isolation; `esc()` and `okColor()` helper guards |
| Protocol / schema | Route engine input fuzzing; bundle manifest with adversarial nodes; policy overlaps and stale classification data; `generated_at` cannot substitute for `ledger_seq`; clock-skew rollback attempts rejected; equal-seq asymmetry (strict vs idempotent); revocation permanence — no API path to un-revoke |
| Auth oracle | Authorization-correctness invariants: advisory/confidence/route fields never grant or imply real access |

---

## How to verify

Every finding and accepted limitation above is exercised by a deterministic, pure-Node test.
Run the full suite:

```bash
node test/security-fixtures.mjs
node test/redteam-fixtures.mjs
node test/key-store-quorum-redteam.mjs
node test/trust-root-adversarial.test.mjs
node test/rendering-adversarial.test.mjs
node test/policy-fuzzer.mjs
node test/auth-oracle-fuzz.test.mjs
node test/regulated-sim-fixtures.mjs
```

Or run everything at once (these are included in the CI suite):

```bash
for f in test/*.mjs; do echo "== $f =="; node "$f"; done
```

No network access, no credentials, no external dependencies beyond Node.js 18+.

---

## Scope and what was not tested

**In scope:** injection in generated artifacts, secret leakage through projections, the local
MCP server, the indexer's privacy defaults, the local trust root (key store, ledger, freshness
guards), the rendering pipeline, and the protocol/schema layer.

**Out of scope:** issues that require an attacker to already control your machine or your
repository's contents with your knowledge. KnoSky is a local-first tool with no hosted
backend; a remote-code-execution finding would require a hosting surface that does not exist.

---

See also: [SECURITY.md](SECURITY.md) · [PRIVACY.md](PRIVACY.md) · [LIMITATIONS.md](LIMITATIONS.md)
