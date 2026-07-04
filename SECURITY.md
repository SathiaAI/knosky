# Security Policy

KnoSky is a **local-first** tool: it runs on your machine, indexes your own folder, and writes a self-contained city file. It does not upload your source and has no hosted backend. The security surface that matters is the **generated artifact** (the city HTML / `city-data.json`) and the local indexer/MCP.

## Supported versions

The latest release on the `main` branch is supported. KnoSky is pre-1.0; please run the newest version before reporting an issue.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for anything exploitable.

- Preferred: GitHub **"Report a vulnerability"** (Security → Advisories) on this repository, which opens a private channel.
- We aim to acknowledge reports within **5 business days** and to publish a fix or mitigation for confirmed issues as quickly as is practical.

When reporting, please include: the version/commit, steps to reproduce, and the impact you observed. A minimal proof-of-concept (e.g., a tiny repo or `city-data.json` that triggers the issue) helps a lot.

## Safe testing guidelines

- Test only against repositories and folders **you own or control**.
- Do not include real secrets or third-party personal data in proof-of-concept artifacts.
- Do not perform testing that degrades the service for others (there is no shared service; this is a local tool).

## Handling generated artifacts (for users)

- A generated city embeds **file names, paths, headings, and short excerpts** — not full file bodies. Treat a generated file as you would a directory listing with snippets.
- Build with `--share-safe` before sharing: it strips the absolute root path (basename only), runs a fail-closed secret scan, and prints a safety report. Builds **fail closed** if a secret-like value is detected (override only with `--allow-leaks`).
- Open city files you did not generate the same way you would any untrusted HTML.

## Trust model

KnoSky's local trust model applies the core security principles of TUF — role separation, threshold signing, survivable key compromise, and freshness-guaranteed revocation — adapted from TUF's server-oriented update distribution to a fully local, no-egress agentic environment, with attestation formats based on in-toto/DSSE.

## Known boundary conditions

**N=2 key-store quorum (D-163):** when a key store holds exactly 2 non-revoked keys, the revocation quorum formula (`Math.floor(peers/2)+1`) reduces to 1, meaning the sole peer key alone can revoke the other. This is mathematically unavoidable at N=2, is an accepted limitation (not a defect), and is explicitly exercised by red-team scenario RT-KS-001 (`test/key-store-quorum-redteam.mjs`). Deployments that require real threshold protection must maintain N≥3 non-revoked keys at all times.

**M=0 sole-key self-revocation (D-167):** when a key store has been reduced to exactly 1 non-revoked key (via prior legitimate revocations), `revokeKey()` allows that key to be revoked with zero approvals (`required = 0`). This is an intentional design choice — a *self-wipe*, not a third-party bypass. Requiring peer approval when no peers exist would make a compromised last key permanently irrevocable, which is a worse outcome. D-167's quorum protection is meaningful only at N≥3; this is the N=1 edge of the same quorum curve. **Caller-identity note:** `revokeKey()` does not currently authenticate the caller as the holder of the key being revoked — it authorizes the *state* (M=0), not the *caller*. `revokeKey` has no production call sites today (enforced by an automated whole-repo scan, `test/key-store-quorum-redteam.mjs`), so this is not a live exploitable path. **This is not a simple fix:** each key's raw material (`KeyEntry.raw`) lives inside the same `ks` object `revokeKey` receives, so any caller with access to `ks` already has direct read access to every key's raw material — a self-signature check bolted onto `revokeKey` today would be trivially satisfiable by any caller (they can just read `raw` and compute the expected signature themselves), providing no real security. A genuine fix requires an architectural change — key material stored somewhere the `ks`-holding caller cannot directly read (e.g. an OS keychain or a separate process boundary) — not a signature parameter added to the existing function. Tracked and scoped as such: SAT-478. Explicitly exercised by red-team scenario RT-KS-002 (`test/key-store-quorum-redteam.mjs`). Cross-reference: SAT-472 (quorum design doc comment), SAT-477, SAT-478.

## Local trust boundary

HWM-file integrity (the `ledger.hwm.json` high-water-mark guard introduced in SAT-443) is part of KnoSky's local trust boundary: an attacker who can delete or modify that file — or any file under KnoSky's data directory — already has local write access to the machine, which is equivalent to controlling KnoSky's own code. This is the same boundary D-164 draws for the trust root generally; no fully-local, no-egress tool can defend against an attacker with local filesystem write access without a remote or hardware anchor, which would violate KnoSky's core no-egress design principle.

## Opt-in org export (SAT-546)

KnoSky's core tool -- everything an `npm install knosky` / `npx knosky` user
runs (the indexer, the local MCP server, `bin/knosky.mjs`) -- is no-egress by
default and always. This section makes that guarantee's exact scope explicit,
because `daemon/export-daemon.mjs` is a real, deliberate exception with a
narrow, opt-in, structurally-separate boundary:

- **Not shipped to npm.** `daemon/` is not listed in `package.json` "files".
  An ordinary user who installs KnoSky from the npm registry does not receive
  this file at all -- it cannot be invoked by accident. It only exists for an
  organization that clones this source repository specifically to run its own
  export process.
- **Never imported by the evaluator.** `core/append-only-checkpoint.mjs`, the
  MCP server, and every other evaluator-path module never import anything from
  `daemon/` -- enforced both structurally (the file does not exist under
  `core/`) and by an automated source-scan test (`test/append-only-checkpoint.test.mjs`,
  F02-018/F02-019).
- **Off by default, explicit config required.** The daemon does nothing
  without a config file the org must create themselves, naming an HTTPS
  destination **the org itself owns** -- never a Sathia/KnoSky-operated
  endpoint. `parseExportConfig` rejects a missing, disabled, or non-HTTPS
  config.
- **Loud at runtime.** Starting the daemon prints an explicit warning that it
  makes real network calls and is not part of the no-egress core tool, before
  doing anything else.
- **Purpose:** a free, always-on, append-only secondary checkpoint
  (append-only local file, `core/append-only-checkpoint.mjs`) with an
  *optional* path for an org to also mirror that checkpoint to storage it
  controls. The local file is the guarantee; the export daemon is a
  convenience layered on top of it, never a replacement or a dependency of it.

## Scope

In scope: injection in generated artifacts, secret leakage through projections, the local MCP server, and the indexer's privacy defaults. Out of scope: issues that require an attacker to already control your machine or your repository's contents with your knowledge.
