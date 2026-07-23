# Owner demo — Enterprise Phase 2 (private adversarial gauntlet)

**Greenlight:** `GREENLIGHT ENT PHASE 2` (Paul 2026-07-23)  
**Depends on:** ENT PHASE 1 DEMO GREEN  
**Scope:** Synthetic hosts only · attacker/probe/reviewer families · analysis + rollup · **private**  
**Not yet:** public pack publish · Phase 3 architecture intel · live multi-provider spend (optional with flags)

---

## Plain English

We create **fake (synthetic) mini-projects**, run **attack-style checks** and **review**, and produce a report.  
No customer code. Nothing is auto-published.  
If everything holds: **PRIVATE GREEN**. Only then do we discuss going public.

---

## Commands (from engine folder)

You must be in:

`<path-to>\knosky`

### 1) List scenarios

```text
node bin/knosky.mjs adversarial list
```

### 2) Run full private gauntlet (no LLM $)

Have frameworks for attacker, probe, reviewer (deterministic + rules).  
Optional models stay off unless you ask.

```text
node bin/knosky.mjs adversarial run
```

Expect:

- Aff table of 8 scenarios  
- **PRIVATE GREEN** (or NOT GREEN with ids to fix)  
- `Artifacts: <folder>` with `gauntlet-rollup.md`

### 3) Optional: residual automated test

```text
node test/enterprise-phase2-gauntlet.test.mjs
```

Expect: **ALL PASS**

### 4) Optional: live LLM reviewer (uses API key + spend)

Only if you want Haiku/OpenRouter to write extra review text:

```text
set KS_ADV_LLM=1
node bin/knosky.mjs adversarial run --llm
```

Default demo does **not** need this.

---

## What good looks like

| Check | Good |
| :--- | :--- |
| Synthetic hosts | Folder marked NOT customer data |
| Secret scenario | Index **blocks** dirty headings |
| Ignore .env | Secret not in city (or blocked) |
| Paths | No absolute machine paths in share-safe city |
| Traversal | Outside-root resolve denied |
| Injection README | Indexed as data; map stays read-only |
| Stale | Detects source newer than city |
| Huge file | Completes or fails cleanly (no hang) |
| Rollup | private:true, publishable:false |

---

## After PRIVATE GREEN

Options (Owner decide later):

| | Choice |
| :--- | :--- |
| A | Keep pack private |
| B | Partners only |
| C | Public open pack (requires `APPROVE ENT ADVERSARIAL PUBLISH`) |

Do **not** market “attack tested” until you pick C (or B with clear scope).

---

## Honesty

- Phase 2 is **private gauntlet evidence**, not a SOC2 certificate.  
- Deterministic families always run; live multi-model is opt-in.  
- Windows F0.5 egress warn from Phase 1 still applies.

Pass phrase when you have walked it (optional but good):

```text
ENT ADVERSARIAL PRIVATE GREEN
```

---

## Owner live result (2026-07-23)

**Status: ENT ADVERSARIAL PRIVATE GREEN**

| Check | Result |
| :--- | :--- |
| `adversarial list` | 8 scenarios |
| `adversarial run --llm` (OpenRouter loaded) | **PRIVATE GREEN · 8 / 0 / 8** |
| Artifacts | Temp `knosky-adv-gauntlet-XXXX` rollup opened |
| `test/enterprise-phase2-gauntlet.test.mjs` | **ALL PASS** |

Publish: **not** automatic — Owner still chooses keep private / partners / public (`APPROVE ENT ADVERSARIAL PUBLISH` only if public).
