# Owner demo — Enterprise Phase 3 (architecture intelligence)

**Greenlight:** `GREENLIGHT ENT PHASE 3` (Paul 2026-07-23)  
**Publish pack:** still **private** (P = A)  
**Scope:** District scores — docs / ownership / tests / churn / drift / risk · leader table · local only  

---

## Plain English

After the map exists, KnoSky can now print an **architect’s hangboard**:

- Which **districts** look thin on docs  
- Who **owns** what (if CODEOWNERS exists)  
- Where **tests** sit next to code  
- Where **churn** is hot  
- How the map **grew/shrunk** vs last snapshot  
- A simple **risk** attention order  

These are **local proxies for pilots**, not a full enterprise static-analysis product and not uploaded anywhere.

---

## Prerequisites

1. You already ran Enterprise Mode so `.knosky/city-data.json` exists (Phase 1).  
2. Optional: `CODEOWNERS` or `.github/CODEOWNERS` in the repo for ownership scores.  
3. Second run needed before **drift %** looks interesting (first run baselines).

---

## Commands (from engine folder)

```text
cd "<path-to>\knosky"
```

### 1) Ensure city exists (if needed)

```text
node bin/knosky.mjs enterprise . --no-open --no-serve
```

### 2) Run architecture intelligence

```text
node bin/knosky.mjs intel .
```

**Expect:** markdown table of districts + paths:

- `.knosky\architecture-intel.md`  
- `.knosky\architecture-intel.json`

### 3) Optional JSON

```text
node bin/knosky.mjs intel . --json
```

### 4) Residual test

```text
node test/enterprise-phase3-intel.test.mjs
```

**Expect:** `ALL PASS`

### 5) Second intel run (drift)

Run enterprise or intel again later; prior city is stored as `city-data.prev.json` for comparison.

---

## How to read the table

| Column | Higher usually means |
| :--- | :--- |
| Docs | More doc-like nodes vs code in that district |
| Own% | More files matched CODEOWNERS |
| Tests | Better test-path adjacency to code |
| Churn | Calmer change heat |
| Risk | Safer (attention list sorts low risk_score first) |
| Level | low / watch / elevated |

Without CODEOWNERS, **Own%** will look weak — that’s expected honesty.

---

## After you’re happy

```text
ENT PHASE 3 DEMO GREEN
```

---

## Honesty

- Local only · no cloud upload of intel  
- Proxies, not CVE scanner  
- Adversarial pack remains **private** (DEC-121)  
- Windows still no fake no-egress badge

---

## Owner live result (2026-07-23)

**Status: ENT PHASE 3 DEMO GREEN**

Paul accepted Phase 3 architecture intelligence demo.
Adversarial pack remains private (DEC-121).
