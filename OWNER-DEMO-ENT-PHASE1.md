# Owner demo — Enterprise Phase 1 (proofware)

**Greenlight:** `GREENLIGHT ENT PHASE 1` (Paul 2026-07-23)  
**Scope:** Enterprise / Regulated named mode + security report + audit pack/verify + RO guarantee docs/tests.  
**Not yet:** multi-model synthetic adversarial gauntlet (Phase 2) · full architecture intel overlays (Phase 3).

## What you can try (PowerShell-safe — plain commands only)

Open a terminal in the knosky repo (or any pilot folder you own).

### 1) Enterprise Mode index + security report

```text
node bin/knosky.mjs enterprise . --no-open --no-serve
```

Expect under `.knosky/`:

- `city-data.json` / `city.html`
- `config.yml` (enterprise profile)
- `security-report.json`
- `security-summary.md`
- `mcp-capability-matrix.json`

### 2) Doctor shows Enterprise rows

```text
node bin/knosky.mjs doctor --json
```

Look for ENT-MODE / ENT-SEC / ENT-RO style rows when config mode is enterprise.

### 3) Audit pack + verify (CISO-style)

```text
node bin/knosky.mjs audit pack --root .
```

Note the printed `bundleDir`, then:

```text
node bin/knosky.mjs audit verify PASTE_BUNDLE_DIR_HERE
```

Expect `RESULT: PASS`.

### 4) Phase 1 residual tests

```text
node test/enterprise-phase1.test.mjs
```

Expect `ALL PASS`.

### 5) Secret fail-closed (still)

A doc with a fake AWS-like key should still **block** enterprise index (share-safe fail-closed). Covered in the residual test.

## What to say after you walk it

```text
ENT PHASE 1 DEMO GREEN
```

That unlocks **Phase 2** (multi-model synthetic adversarial host + families + analysis/review) per DEC-119 / ENT-TRACKER.

## Paths

| Item | Location |
| :--- | :--- |
| Engine | `session-2-knosky/research/knosky/` |
| RO guarantee | `docs/READ_ONLY_GUARANTEE.md` |
| Seller sheet | `session-2-knosky/surfaces/com/ENTERPRISE-SELLER-SHEET.md` |
| Tracker | `session-2-knosky/session-3/ENT-TRACKER.md` |

## Honesty

- Map tools = read-only navigation.  
- Mode B = separate governed column.  
- L3 = foundation only.  
- No public “attack tested” claim until Phase 2 private green + your publish call.

---

## Owner live result (2026-07-23)

**Status: ENT PHASE 1 DEMO GREEN**

| Check | Result |
| :--- | :--- |
| `enterprise . --no-open --no-serve` | OK — 164 nodes, secrets 0, risk LOW, provenance 100%, security report written |
| `doctor` | ENT-MODE enterprise · ENT-SEC present · 11 ok / 1 warn (Windows F0.5) / 0 fail |
| `audit verify` bundle `...124429` | **RESULT: PASS** |
| `test/enterprise-phase1.test.mjs` | **ALL PASS** |

Next gate phrase for Phase 2 residual start (if not already implied): continue / “go Phase 2”.
