# KnoSky

**GPS for AI agents** — map any local repo/docs folder, route assistants to the right files, optional Mode B allow/deny receipts. City view is the human skin. Runs on your machine. Free.

> *Born from building [Sathia](https://sathia.ai).*

npm: **`knosky@0.7.0`** (`npx knosky@latest`) · Sites: [knosky.com](https://knosky.com) · [knosky.wiki](https://knosky.wiki)

---

> **Trust model (approved wording):** KnoSky's local trust model applies the core security principles of TUF — role separation, threshold signing, survivable key compromise, and freshness-guaranteed revocation — adapted from TUF's server-oriented update distribution to a fully local, no-egress agentic environment, with attestation formats based on in-toto/DSSE.

## See it in 10 seconds

Open **[`demo/knosky-demo.html`](./demo/knosky-demo.html)** in your browser (double-click — self-contained). Sample project as a city. Then point KnoSky at yours.

---

## The problem

Projects outgrow human memory of “which file.” Agentic tools make thrash expensive — tokens, tool calls, late answers. A file tree lists names; it does not give assistants a **shared map and route**.

## What you get

> **Measured (SAT-439, 5 tasks, naive agent vs KnoSky-guided):**
> **68% fewer tokens · 70% fewer tool calls · 6× faster to the right file**
> *(Guided: correct 5/5. Naive: found target 3/5, correct 0/5.)*

- **See the shape of the work** — districts and buildings over a raw tree (human skin).
- **Route agents to the right node** — MCP map + optional governed route.
- **Local-first** — default path does not upload your source; $0 to keep the map fresh.
- **Honest ceilings** — never claim higher than `knosky doctor` on *this* install.

**Not** a code-intelligence product, IDE, or cloud body-store. Complementary GPS layer.

## Who it's for

Builders shipping with Claude / Cursor / Codex / Hermes who want less thrash — and leads who want one navigation + optional permission story across tools.

---

## Quickstart

```bash
npx knosky@latest .
```

Indexes the current folder, builds the city, prints MCP config + starter prompts, starts the local connector.  
Flags: `--no-open`, `--no-serve`. Point elsewhere: `npx knosky@latest /path/to/repo`.

Clone path:

```bash
git clone https://github.com/SathiaAI/knosky && cd knosky && npm install && node bin/knosky.mjs .
```

**Requirements:** [Node.js](https://nodejs.org) **20+** (see `package.json` engines; 18 may work for older tags).

After install:

```bash
npx knosky@latest doctor
```

---

## How it works

### 1. Map (local index)

```bash
node core/fs-indexer.mjs --root /path/to/your/repo --out city-data.json --share-safe
node renderer/build-rich.mjs city-data.json city.html
```

Or simply `npx knosky@latest .` (wraps map + city + connector).

Top-level folders → **districts**, files → **buildings**, links back to live source.  
`--share-safe` strips absolute roots and **fails closed** on secret-like values.

### 2. Connect an assistant (MCP) — DEC-108 menu

SSOT: [`ssot/tool-menu.json`](./ssot/tool-menu.json) · codes: [`ssot/decision-codes.json`](./ssot/decision-codes.json) · ladder: [`ssot/ladder-l0-l3.md`](./ssot/ladder-l0-l3.md).  
Consumer packs: [`packs/`](./packs/) (Hermes · Claude Code · Cursor · Codex · P1 VS Code / Greptile recipe / GHA).

```bash
cd mcp && npm install && cd ..
claude mcp add knosky \
  -e KC_CITY=/abs/path/city-data.json \
  -e KC_PROFILE=coding \
  -- node /abs/path/mcp/server.mjs
```

JSON shape (Cursor / Desktop / Codex — key name may be `mcpServers` or `mcp_servers`):

```json
"knosky": {
  "command": "node",
  "args": ["/abs/path/mcp/server.mjs"],
  "env": {
    "KC_CITY": "/abs/path/city-data.json",
    "KC_PROFILE": "coding"
  }
}
```

| Profile (`KC_PROFILE`) | For | Tools |
| :--- | :--- | :--- |
| **coding** (default packs) | Day-to-day agents | Tier 0 map + Tier 1 governed |
| **security** | Operators / verify | Coding + `kc_audit_query` / `kc_audit_verify` |
| **advisory** | Explicit non-authorizing explore | Map + labeled Mode A `kc_route` |

**Mode A vs Mode B**

| Mode | On the wire | Meaning |
| :--- | :--- | :--- |
| **A** | `ADVISORY_UNAUTH` | Tips only — not policy-certified, not swarm-safe |
| **B** | `ALLOW` / `DENY_*` (+ receipt on ALLOW) | Identity + policy + audit before authorized claims |

Default coding profile uses **Mode B** for governed tools. Mode A stays labeled.

**Tool menu (freeze)**

| Tier | Tools | Authorizing? |
| :--- | :--- | :---: |
| **0 map** | `kc_search`, `kc_get_node`, `kc_list_categories`, `kc_get_provenance`, `kc_related` | No |
| **1 governed** | `kc_route` (dual-mode), `kc_bundle`, `kc_policy_check` | Yes on Mode B `ALLOW` |
| **Security only** | `kc_audit_query`, `kc_audit_verify` | Audit — not on coding packs |

**Mode B lease (governed calls):**

```bash
node bin/knosky.mjs agent-register --domain .knosky --agent my-agent --role coder
```

Pass **`leaseId`** into `kc_route` / `kc_policy_check` / `kc_bundle`. Payload `agentId` alone is not identity.

Closed decision codes:  
`ALLOW` · `DENY` · `DENY_IDENTITY` · `DENY_POLICY` · `DENY_AUDIT` · `DENY_FRESHNESS` · `DENY_EVIDENCE` · `ERROR_INVALID_INPUT` · `ERROR_INDEX` · `ADVISORY_UNAUTH`

### 3. Guarantee ladder (never over-claim)

| L | Name | Promise |
| :---: | :--- | :--- |
| **L0** | Local map | Index + navigate locally; no KnoSky upload by default |
| **L1** | Share-safe | Fail-closed secret controls before share artifacts |
| **L2** | Governed evaluator | Mode B identity + policy + audit (or safe DENY) |
| **L3** | Swarm domain | Multi-agent **coordinator** on Mode B (below) |

### 4. L3 swarm coordinator — what works (Wave 1 foundation)

Implemented in-process + CLI on the **local trust domain** (not a multi-tenant cloud swarm product):

| Capability | Status (validated) |
| :--- | :--- |
| Distinct agent identities + leases | **Works** — issue / list / bind via domain store |
| Lease expire (holder) + revoke (holder or operator) | **Works** — foreign revoke denied |
| File + district **traffic claims** (not VCS locks) | **Works** |
| Claim conflict DENY + FIFO wait position | **Works** (fairness) |
| Quotas + backpressure (`maxClaimsPerAgent`, action windows) | **Works** |
| Claim **requires `leaseId`** | **Works** |
| Multi-agent audit receipts (`meta.swarm`, hash chain) | **Works** |
| Anti-probe on rapid DENY floods | **Works** |
| Heatmap snapshot + `knosky swarm status` | **Works** (CLI ops skin, not a full GUI console) |
| `knosky swarm bench` | **Works** (conflict + quota measure) |
| Mode B composition (dual-op elevated classes, etc.) | **Works** — required under L3 |

**Public claim rules for L3**

- You **may** say: local swarm **coordinator foundation**, lease-governed multi-agent routing, heatmap/status/bench tools exist.
- You **must not** say: production “**swarm-safe fleet** at every install,” multi-tenant cloud isolation, or L3 ready without `knosky doctor` ceiling on *that* domain.
- Doctor marks L3 modules as **FOUNDATION present** and keeps ladder guidance as **info** — not a green “ship swarm everywhere” badge.

```bash
npx knosky@latest swarm status --domain .knosky
npx knosky@latest swarm bench
npx knosky@latest doctor
```

Windows: network lockdown is **unsupported/inactive** at runtime for this CLI until packaging proves otherwise — see [LIMITATIONS.md](./LIMITATIONS.md).

### 5. PR navigation comments (GitHub Action — PR-GPS)

Advisory neighbor only (does not gate merge by default):

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: SathiaAI/knosky@v0.5.0   # pin newer tag when you cut GitHub Action releases
  with:
    base: ${{ github.event.pull_request.base.sha }}
    head: ${{ github.event.pull_request.head.sha }}
```

---

## What it is **not** (on purpose)

- **Not code intelligence / an IDE** — map + route + optional receipts; deep Q&A stays with coding agents.
- **Not a cloud vault of your source** — local trust domain (DEC-109).
- **Not a body store** — pointers and short projections; live files stay source of truth (DEC-107).
- **Not “zero data risk”** or blanket swarm-safe — see privacy + doctor ceilings.

## Privacy & safety

- Local by default; indexing skips `.git`, `node_modules`, secrets-ish paths, ignore files.
- Scrubs common secret/PII patterns; `--share-safe` fails closed on hits.
- Generated cities embed data as inert JSON and escape names.

More: [PRIVACY.md](./PRIVACY.md) · [LIMITATIONS.md](./LIMITATIONS.md) · [SECURITY.md](./SECURITY.md) · [CHANGELOG.md](./CHANGELOG.md) · [knosky.wiki](https://knosky.wiki/) · [compare](./wiki/comparison.md)

## License & credits

**[Functional Source License (FSL-1.1-MIT)](./LICENSE.md)** — free to use; no competing hosted repackage; converts to MIT two years after each release. “KnoSky” trademark of the author.

City art: **[Kenney](https://kenney.nl)** (CC0) — [CREDITS.md](./CREDITS.md).
