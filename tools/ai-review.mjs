// KnoSky AI Review — adversarial + claims-discipline gate for pull requests.
// Ported from Sathia's tools/ai-review.mjs (proven pattern), re-scoped for KnoSky's own rules:
// no-egress, approved TUF-evolution wording, scope-match/stub detection, local-only security logic.
// Posts a single GitHub PR review with severity-tagged findings. Any CRITICAL => REQUEST_CHANGES (blocks merge).
// D-166 (SAT-467): any P0/critical or ambiguous result (degraded reviewers) escalates to Paul, never silent.
// Env: LITELLM_REVIEW_KEY, LITELLM_BASE_URL, GITHUB_TOKEN, PR_NUMBER, REPO, DIFF_PATH.
import fs from 'fs';
import https from 'https';
import { shouldEscalateToPaul } from '../core/escalate.mjs';

const { LITELLM_REVIEW_KEY, LITELLM_BASE_URL, GITHUB_TOKEN, PR_NUMBER, REPO, DIFF_PATH } = process.env;
const log = m => process.stdout.write(`[ai-review] ${m}\n`);

// Graceful skip when secrets aren't available (e.g. a fork-originated PR run, where GitHub
// withholds repo secrets by design) — advisory-only skip, never a false "clean" pass reported
// as a real review, and never a hard failure that blocks external contributions outright.
if (!LITELLM_REVIEW_KEY || !LITELLM_BASE_URL) {
  log('LITELLM_REVIEW_KEY/LITELLM_BASE_URL not available (likely a fork PR run) — skipping AI review; relies on secrets-scan + human review for this PR.');
  process.exit(0);
}

const diff = fs.readFileSync(DIFF_PATH || '/tmp/pr.diff', 'utf8');
if (!diff.trim()) { log('empty diff — nothing to review'); process.exit(0); }

// Never transmit the review key over a non-HTTPS endpoint.
if (!/^https:\/\//i.test(LITELLM_BASE_URL || '')) {
  log('refusing to run: LITELLM_BASE_URL must be an https:// endpoint — skipped to avoid sending the review key in plaintext.');
  process.exit(0);
}

// Redact secret-shaped strings from the diff before sending it to the reviewer model. Defense in
// depth alongside the separate secrets-scan job.
function redactSecrets(text) {
  return text
    .replace(/eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g, '[REDACTED_JWT]')
    .replace(/\bgithub_pat_[A-Za-z0-9_]{20,}/g, '[REDACTED_GH_PAT]')
    .replace(/\bgh[posru]_[A-Za-z0-9]{20,}/g, '[REDACTED_GH_TOKEN]')
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED_AWS_KEY]')
    .replace(/\bAIza[0-9A-Za-z_\-]{35}\b/g, '[REDACTED_GOOGLE_KEY]')
    .replace(/(Bearer\s+)[A-Za-z0-9._\-]{12,}/gi, '$1[REDACTED]')
    .replace(/(['"]?(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|signing[_-]?secret)['"]?\s*[:=]\s*['"]?)[^\s'"]{8,}/gi, '$1[REDACTED]');
}

const TRUNCATED = diff.length > 60000;
const capped = TRUNCATED ? diff.slice(0, 60000) + '\n[...diff truncated for review...]' : diff;
const DIFF = redactSecrets(capped);

const fileCount = (diff.match(/^diff --git /gm) || []).length;
const sensitive = /(core\/(key-store|ledger|freshness|trust|contract)|SECURITY|README|wiki\/|docs\/)/i.test(diff);

const FOCUS = `Review this diff against KnoSky's specific non-negotiable rules, in order of priority:

1. NO EGRESS (highest priority): KnoSky is local-first and must never connect out, transmit telemetry, or make any third-party network call as part of its default/core runtime behavior. Flag any new outbound HTTP call, new dependency that talks to an external service, or anything that could leak local data off the machine, UNLESS it is clearly scoped as test/fixture code (e.g. in test/ or sim/) that is explicitly invoked for a controlled pressure-test and does not run by default.
2. CLAIMS DISCIPLINE: the ONLY approved sentence describing KnoSky's relationship to TUF is: "KnoSky's local trust model applies the core security principles of TUF — role separation, threshold signing, survivable key compromise, and freshness-guaranteed revocation — adapted from TUF's server-oriented update distribution to a fully local, no-egress agentic environment, with attestation formats based on in-toto/DSSE." Flag ANY deviation from this exact wording where it appears, and flag any use of "TUF-compatible", "implements TUF", "tamper-evident", "zero-trust", "enterprise-grade", or "SOC2" anywhere in docs/README/wiki copy.
3. SECURITY LOGIC: authentication/authorization/key-management logic must not have a single point of takeover — e.g. a key-revocation or trust-modification action must require more than unilateral action from the thing being revoked/modified. Flag missing authorization/quorum checks on security-critical state changes (key rotation, revocation, ledger writes, policy changes).
4. SCOPE MATCH / STUB DETECTION: does the diff actually implement what its PR title/description claims, and is it actually wired into the code paths that use it (not a correctly-tested but orphaned/unused module)? Flag PRs that claim to depend on or integrate with another component but don't actually call into it.
5. SECRETS: any hardcoded API keys, tokens, or credentials.

IGNORE formatting, naming, import order, and style.
For each finding output a line: SEVERITY|file|hint  where SEVERITY is CRITICAL, WARNING, or INFO.
CRITICAL = a concrete, provable defect matching one of the 5 categories above, INTRODUCED BY THIS DIFF, visible in the shown lines. Do NOT raise CRITICAL for something that depends on the absence of code you cannot see elsewhere in the file/repo — downgrade that to WARNING phrased "verify in full file". NEVER raise a CRITICAL asserting a function/method "expects", "requires", or has the "wrong" signature, parameter order, or call shape unless that exact signature is visible and contradicted within the shown diff lines themselves -- a mismatch inferred from training data or assumption, not from lines actually shown, is a WARNING phrased "verify signature in full file", never a CRITICAL (root-caused from a real false positive on knothread PR #14/#16, 2026-08-15 -- see core/escalate.mjs). When unsure between CRITICAL and WARNING, choose WARNING. WARNING = should fix, informational. INFO = minor (will be suppressed). If nothing material: output exactly NONE.`;

const ROLES = [
  { model: 'sathia-standard', name: 'QA',          sys: 'You are a meticulous QA reviewer for KnoSky, a local-first no-egress developer tool. ' + FOCUS },
  { model: 'sathia-deepseek', name: 'Adversarial',  sys: 'You are an adversarial security reviewer from a different model family, trying to BREAK this code or catch an overstated claim. ' + FOCUS },
];
if (sensitive || fileCount > 3) ROLES.push({ model: 'sathia-hardened-1', name: 'Architect', sys: 'You are a principal architect reviewing KnoSky trust/security-critical code for system coherence. ' + FOCUS });

function llm(model, sys) {
  return new Promise((resolve) => {
    const body = JSON.stringify({ model, messages: [{ role: 'system', content: sys }, { role: 'user', content: 'PR DIFF:\n\n' + DIFF }], max_tokens: 1200, temperature: 0.2 });
    const u = new URL(LITELLM_BASE_URL);
    const basePath = u.pathname.replace(/\/+$/, '').replace(/\/v1$/, '');
    const req = https.request({ hostname: u.hostname, port: u.port || 443, path: `${basePath}/v1/chat/completions`, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${LITELLM_REVIEW_KEY}`, 'Content-Length': Buffer.byteLength(body) } },
      res => { const c = []; res.on('data', d => c.push(d)); res.on('end', () => {
        const sc = res.statusCode || 0;
        if (sc < 200 || sc >= 300) { resolve({ ok: false, text: '', err: `HTTP ${sc}` }); return; }
        try { resolve({ ok: true, text: JSON.parse(Buffer.concat(c).toString()).choices?.[0]?.message?.content || 'NONE', err: null }); }
        catch { resolve({ ok: false, text: '', err: 'unparseable response' }); }
      }); });
    req.on('error', e => resolve({ ok: false, text: '', err: e.message || 'request error' }));
    req.setTimeout(180000, () => req.destroy(new Error('llm timeout 180s')));
    req.write(body); req.end();
  });
}

function parse(role, text) {
  if (!text || /^\s*NONE\s*$/i.test(text.trim())) return [];
  return text.split('\n').map(l => l.trim()).filter(l => /^(CRITICAL|WARNING|INFO)\|/i.test(l))
    .map(l => { const [sev, file, ...rest] = l.split('|'); return { role, sev: sev.toUpperCase(), file: (file || '').trim(), hint: rest.join('|').trim() }; })
    .filter(f => f.sev !== 'INFO');
}

function gh(method, path, payload) {
  return new Promise((resolve, reject) => {
    const body = payload ? JSON.stringify(payload) : null;
    const req = https.request({ hostname: 'api.github.com', path, method,
      headers: { 'User-Agent': 'knosky-ai-review', 'Authorization': `Bearer ${GITHUB_TOKEN}`, 'Accept': 'application/vnd.github+json', ...(body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {}) } },
      res => { const c = []; res.on('data', d => c.push(d)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(c).toString() })); });
    req.on('error', reject);
    req.setTimeout(30000, () => req.destroy(new Error('github api timeout 30s')));
    if (body) req.write(body); req.end();
  });
}

const roleResults = await Promise.all(ROLES.map(async r => { log(`running ${r.name} (${r.model})...`); const out = await llm(r.model, r.sys); if (!out.ok) log(`${r.name} failed: ${out.err}`); return { role: r.name, ...out }; }));
const failed = roleResults.filter(r => !r.ok);
const findings = roleResults.filter(r => r.ok).flatMap(r => parse(r.role, r.text));
const criticals = findings.filter(f => f.sev === 'CRITICAL');
const warnings = findings.filter(f => f.sev === 'WARNING');

// D-166 (SAT-467): any P0/critical or ambiguous result must surface to Paul, never proceed silently.
// D-166 (SAT-466): zero-P0/critical + all reviewers succeeded → auto-approve (canAutoPublish).
const { escalate, reasons, paulMessage, canAutoPublish } = shouldEscalateToPaul({ criticals, failed, total: ROLES.length });

let md = `## 🤖 KnoSky AI Review\n\n`;
md += ROLES.length === 3 ? `Reviewers: QA · Adversarial (DeepSeek) · **Architect (Opus)** — sensitive/large diff.\n\n` : `Reviewers: QA · Adversarial (DeepSeek).\n\n`;
if (TRUNCATED) md += `⚠️ **Diff truncated at 60 KB** — hunks past that point were NOT reviewed.\n\n`;
if (failed.length) md += `⚠️ **Reviewer degraded** — ${failed.map(f => `${f.role} (${f.err})`).join(', ')} did not complete${failed.length === ROLES.length ? '. No reviewer succeeded → blocking until re-run.' : '. Result is incomplete (ambiguous) — escalating to Paul.'}\n\n`;
if (!findings.length && !failed.length) md += `✅ No material issues found against KnoSky's no-egress, claims-discipline, and security-logic checklist.\n`;
else if (!findings.length && failed.length && failed.length < ROLES.length) md += `No findings from the reviewers that completed (see degraded note above).\n`;
else if (findings.length) {
  if (criticals.length) md += `### 🔴 CRITICAL (blocks merge) — ${criticals.length}\n` + criticals.map(f => `- **${f.file}** _(${f.role})_: ${f.hint}`).join('\n') + '\n\n';
  if (warnings.length) md += `### 🟡 WARNING (informational) — ${warnings.length}\n` + warnings.map(f => `- **${f.file}** _(${f.role})_: ${f.hint}`).join('\n') + '\n\n';
  if (!escalate) md += `\nNo blockers — warnings are informational.`;
}
if (paulMessage) md += `\n**${paulMessage}**`;

if (process.env.REVIEW_LOCAL) {
  process.stdout.write('\n' + md + '\n');
  log(`LOCAL gate: criticals=${criticals.length} warnings=${warnings.length} failed=${failed.length} escalate=${escalate} canAutoPublish=${canAutoPublish} reasons=${JSON.stringify(reasons)}`);
  process.exit(escalate ? 1 : 0);
}
// SCOPE FIX (D-173, post-PR#47 review, Paul-directed 2026-07-02): this file is the GENERAL
// PR review gate -- security-review.yml triggers it on every PR to main, not just release
// PRs. D-166 only pre-authorized ONE narrow thing: the red-team suite (SAT-437) gating the
// npm PUBLISH step with zero human sign-off on a clean pass. It did NOT authorize this
// general gate to unilaterally submit GitHub PR approvals. This file must NEVER post an
// APPROVE review: doing so would let the AI reviewers' own self-assessment single-handedly
// satisfy a review-approval gate, with no independent human or out-of-band check, on every
// PR forever -- including future trust-root/security PRs this gate was never meant to
// auto-clear. canAutoPublish is still computed below (and shown in the review body) purely
// as DATA -- a separate, narrowly-scoped release workflow may consume it later for the actual
// SAT-437/D-166 publish decision, but that consumption never happens here.
const event = escalate ? 'REQUEST_CHANGES' : 'COMMENT';
try { await gh('POST', `/repos/${REPO}/pulls/${PR_NUMBER}/reviews`, { body: md, event }); }
catch (e) { log('post review failed: ' + (e && e.message ? e.message : String(e))); }
if (escalate) { log(`blocking: reasons=${JSON.stringify(reasons)}`); process.exit(1); }
if (canAutoPublish) log(`eligible for D-166 auto-publish per canAutoPublish (zero P0/critical, all reviewers succeeded) -- NOT auto-approved here (D-173); a dedicated release workflow must independently consume this signal.`);
else log(`pass (comment only): warnings=${warnings.length}`);
