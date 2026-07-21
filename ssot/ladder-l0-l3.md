# KnoSky Guarantee Ladder L0–L3 (SSOT)

```yaml
---
id: knosky-ladder-l0-l3
version: 1.0.0
status: draft-freeze
dec: DEC-110
last_updated: 2026-07-19
consumers:
  - README.md / SECURITY.md / PRIVACY.md
  - knosky.com /trust and /product
  - knosky.wiki govern/ladder
  - knosky doctor claim_ceiling
  - pack onboarding blurbs
---
```

## Purpose

Public, checkable promises for installers and agents. **Never claim a higher level than `knosky doctor` reports for that install.**

Related freezes:

- Tool menu → `tool-menu.json` (DEC-108)
- Decision codes → `decision-codes.json` (DEC-108 / DEC-106)
- Architecture → DOC-02; threat model → DOC-05

---

## Ladder at a glance

| Level | Name | One-line promise | Mode |
| :---: | :--- | :--- | :--- |
| **L0** | Local map | Index and navigate locally; **no KnoSky upload by default** | Map / Mode A |
| **L1** | Share-safe artifact | Artifact suitable to share only after **fail-closed secret controls** | Share tooling |
| **L2** | Governed evaluator | **Mode B**: identity + policy + audit receipt (or safe DENY) before authorized routes | Mode B |
| **L3** | Swarm domain | **Full coordinator** on Mode B: leases, quotas, backpressure, claims, fairness, multi-agent audit, anti-probe, ops heatmap, benchmarks | Mode B + L3 |

---

## L0 — Local map

### Promise

- Runs on the operator machine / domain.
- Builds a **map of pointers and short projections**, not a body store (DEC-107).
- Core path does **not** require a KnoSky account or always-on telemetry (DEC-114).

### You may say

- “Local map”, “citations”, “where to look first”, “MCP map tools”

### You must not say

- “Authorized”, “policy-enforced”, “swarm-safe”, “zero data risk”

### Checks (doctor / tests)

- Index builds without required egress
- CONTRACT allowlist: no bodies in index
- Tier 0 tools available

---

## L1 — Share-safe artifact

### Promise

- Share/export path runs **secret-like detection** and **fails closed** on hits (explicit operator override only).
- Absolute roots stripped to basename by default.
- Operator still reviews before publishing (honest residual risk).

### You may say

- “Share-safe city/bundle”, “failed closed on secrets”, “review before share”

### You must not say

- “Guaranteed free of all secrets forever”, “safe for any public unauth multi-tenant host without review”

### Checks

- Seeded secret fixture fails share-safe build
- Safety report emitted
- Demo corpus uses share-safe artifacts only

---

## L2 — Governed evaluator (Mode B)

### Promise

Any claim of **authorized / governed / policy-checked** routing requires:

1. Bound **identity** (authoritative agent; lease store pattern — no payload spoof)
2. **Policy lattice** decision + district classification → authorized subgraph
3. **Audit receipt** written (metadata-only) before ALLOW payload
4. Otherwise **DENY_*** with **no restricted metadata**

Decision codes: see `decision-codes.json` (`ALLOW`, `DENY_*`, errors). Mode A may still exist **only** if labeled `ADVISORY_UNAUTH`.

### You may say

- “Governed route”, “authorized subgraph”, “policy-checked”, “audit-backed decision”

### You must not say

- That plain advisory MCP (today’s unlabeled path) is L2
- “Kernel no-egress proven on Windows” when doctor reports unsupported (F0.5 honesty)

### Checks

- Anonymous governed call → `DENY_IDENTITY`
- Audit failure → `DENY_AUDIT` and no route body
- Policy deny does not leak restricted paths
- Doctor `mode_b_ready` green
- Menu SSOT matches binary

### Platform honesty

| Platform | Lockdown |
| :--- | :--- |
| Linux | Real enforcement path when tools present |
| macOS | Partial / network-oriented |
| Windows | Doctor must report **unsupported/inactive** until packaging proves otherwise |

---

## L3 — Swarm domain (full coordinator)

### Promise (DEC-113 — Wave 1 floor is **full**, not label-only)

On top of green L2:

| Capability | Required |
| :--- | :---: |
| Distinct agent identities | YES |
| Route leases (issue/renew/expire/bind) | YES |
| Quotas | YES |
| Backpressure | YES |
| File/district claims (traffic, not VCS locks) | YES |
| Fairness / conflict rules | YES |
| Multi-agent audit stream | YES |
| Operator swarm dashboard / heatmap | YES |
| Anti-probe defenses | YES |
| Swarm benchmarks | YES |

### You may say

- “Swarm-coordinated”, “lease-governed multi-agent routing”, “domain swarm-safe under policy”

### You must not say

- “Swarm-safe” when only the lease helper exists
- Multi-tenant **cloud** swarm isolation (DEC-109 non-goal)
- Preview-only labeling as the Wave 1 floor (would need **new DEC** to thin)

### Checks

- Doctor `l3_ready` green
- Lease reuse / spoof denials
- Coordinator down + `require_route_lease` → fail closed
- Swarm benchmarks in release gate set
- Claims lint blocks L3 marketing if doctor ceiling < L3

### Prerequisite law

```text
L3 ⊆ requires L2 Mode B identity + policy + audit
```

---

## Claim ceiling algorithm (normative)

```text
ceiling = L0
if share_safe_controls_green: ceiling = max(ceiling, L1)
if mode_b_composition_green and doctor.mode_b_ready: ceiling = max(ceiling, L2)
if full_l3_modules_green and doctor.l3_ready: ceiling = max(ceiling, L3)
if windows and claim needs kernel_lockdown_evidence: do not raise L2 badge on lockdown_is_proven
public_copy.claim_level must be <= ceiling
```

---

## Adoption profiles (language only; detailed FR in DOC-01)

| Profile | Typical ceiling intent |
| :--- | :--- |
| Solo | L0–L1 fast path; explicit Mode A OK |
| Team | L2 Mode B default for governed tools |
| Regulated | L2+ with evidence requirements; security profile; Windows honesty loud |

---

## Metrics relationship (DEC-114)

Ladder honesty is independent of adoption metrics:

- **No always-on telemetry** at any L
- Opt-in counters default **OFF**
- Public benchmarks may support proof without elevating ladder by slogans alone

---

## Banned overclaim phrases (claims lint seeds)

Do not use without matching doctor ceiling + evidence:

- zero-risk / zero data risk  
- fully understands your codebase  
- SOC2 certified (unless true externally)  
- multi-tenant SaaS isolation (W1)  
- swarm-safe (unless L3 green)  
- authorized / policy-enforced (unless L2 green)  
- Windows kernel no-egress guaranteed (unless doctor proves)

---

## Change control

| Version | Date | Notes |
| :--- | :--- | :--- |
| 1.0.0 | 2026-07-19 | Initial SSOT freeze draft for Wave 1 surfaces |

Edits require DEC-110 revisit or superseding DEC; bump version; regenerate README/wiki/com renders.

---

*SSOT ladder — bind all public L0–L3 language to this file.*
