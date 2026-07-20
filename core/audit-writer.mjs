// KnoSky Mode B audit receipt writer (DEC-106).
// Metadata-only hash-chained local ledger. No file bodies. No network.
// Best-effort exclusive seq.lock reduces concurrent multi-agent TOCTOU on ledger_seq.

import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
  openSync,
  closeSync,
  unlinkSync,
} from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { readHwm } from './ledger.mjs';

/**
 * @param {string} domainRoot
 */
export function auditPaths(domainRoot) {
  return {
    root: domainRoot,
    eventsPath: join(domainRoot, 'audit', 'events.ndjson'),
    hwmPath: join(domainRoot, 'audit', 'hwm.json'),
    checkpointPath: join(domainRoot, 'audit', 'checkpoint.ndjson'),
    seqLockPath: join(domainRoot, 'audit', 'seq.lock'),
  };
}

function hashLine(prevHash, bodyObj) {
  const h = createHash('sha256');
  h.update(prevHash || '');
  h.update('\n');
  h.update(JSON.stringify(bodyObj));
  return h.digest('hex');
}

function lastHash(eventsPath) {
  if (!existsSync(eventsPath)) return null;
  const text = readFileSync(eventsPath, 'utf8').trim();
  if (!text) return null;
  const lines = text.split(/\r?\n/);
  for (let i = lines.length - 1; i >= 0; i--) {
    if (!lines[i].trim()) continue;
    try {
      const row = JSON.parse(lines[i]);
      return row.event_hash || null;
    } catch {
      /* keep scanning */
    }
  }
  return null;
}

function writeHwmSoft(hwmPath, seq) {
  if (!Number.isInteger(seq) || seq < 0) {
    throw new TypeError(`ledger_hwm must be a non-negative integer, got: ${JSON.stringify(seq)}`);
  }
  const dir = dirname(hwmPath);
  mkdirSync(dir, { recursive: true });
  const tmp = hwmPath + '.tmp';
  writeFileSync(tmp, JSON.stringify({ ledger_hwm: seq }) + '\n', 'utf8');
  renameSync(tmp, hwmPath);
}

function checkAndAdvanceSoft(seq, hwmPath) {
  if (!Number.isInteger(seq) || seq < 0) {
    return { ok: false, error: `bad seq ${seq}` };
  }
  let hwm = 0;
  try {
    hwm = readHwm(hwmPath);
  } catch (err) {
    return { ok: false, error: err.message || String(err) };
  }
  // Must strictly advance past HWM (assigned under lock after append prep).
  if (seq <= hwm) {
    return {
      ok: false,
      error: `ledger sequence ${seq} must be > high-water mark ${hwm}`,
    };
  }
  try {
    writeHwmSoft(hwmPath, seq);
  } catch (err) {
    return { ok: false, error: err.message || String(err) };
  }
  return { ok: true, seq, hwm };
}

/**
 * Exclusive lock via O_EXCL create of seq.lock.
 * @returns {{ ok:true, release:()=>void } | { ok:false, reason:string }}
 */
function acquireSeqLock(lockPath, { tries = 50, delayMs = 8 } = {}) {
  mkdirSync(dirname(lockPath), { recursive: true });
  for (let i = 0; i < tries; i++) {
    try {
      const fd = openSync(lockPath, 'wx');
      return {
        ok: true,
        release() {
          try {
            closeSync(fd);
          } catch {
            /* ignore */
          }
          try {
            unlinkSync(lockPath);
          } catch {
            /* ignore */
          }
        },
      };
    } catch (err) {
      if (err && (err.code === 'EEXIST' || err.code === 'EPERM')) {
        const end = Date.now() + delayMs;
        while (Date.now() < end) {
          /* brief backoff */
        }
        continue;
      }
      return { ok: false, reason: err && err.message ? err.message : String(err) };
    }
  }
  return { ok: false, reason: 'seq_lock_timeout' };
}

function sanitizeMeta(meta) {
  if (!meta || typeof meta !== 'object') return {};
  const out = {};
  for (const [k, v] of Object.entries(meta)) {
    if (typeof k !== 'string' || k.length > 80) continue;
    if (v == null) continue;
    if (typeof v === 'string') out[k] = v.slice(0, 200);
    else if (typeof v === 'number' || typeof v === 'boolean') out[k] = v;
    else if (Array.isArray(v)) out[k] = v.slice(0, 20).map((x) => String(x).slice(0, 80));
  }
  return out;
}

/**
 * Append a route/swarm decision event and return a receipt.
 * Fail-closed on I/O / HWM / lock errors.
 *
 * @param {object} opts
 * @returns {{ ok:true, receipt_id:string, ledger_seq:number, event_hash:string }
 *          |{ ok:false, reason:string }}
 */
export function writeDecisionReceipt(opts = {}) {
  let lock = null;
  try {
    const {
      domainRoot,
      decision_code,
      agent_id = null,
      principal_id = null,
      tool = null,
      destination = null,
      mode = 'B',
      meta = {},
    } = opts;
    if (!domainRoot || typeof domainRoot !== 'string') {
      return { ok: false, reason: 'missing_domain_root' };
    }
    if (!decision_code || typeof decision_code !== 'string') {
      return { ok: false, reason: 'missing_decision_code' };
    }

    const paths = auditPaths(domainRoot);
    mkdirSync(dirname(paths.eventsPath), { recursive: true });

    lock = acquireSeqLock(paths.seqLockPath);
    if (!lock.ok) {
      return { ok: false, reason: `seq_lock: ${lock.reason}` };
    }

    // Under lock: seq = max(lineCount, hwm) + 1, then append, then HWM.
    const prev = lastHash(paths.eventsPath);
    let lineCount = 0;
    if (existsSync(paths.eventsPath)) {
      const t = readFileSync(paths.eventsPath, 'utf8');
      lineCount = t.split(/\r?\n/).filter(Boolean).length;
    }
    let hwm = 0;
    try {
      hwm = readHwm(paths.hwmPath);
    } catch (err) {
      return { ok: false, reason: `hwm_read: ${err.message || err}` };
    }
    const seq = Math.max(lineCount, hwm) + 1;

    const receipt_id = `rcpt_${randomUUID().replace(/-/g, '').slice(0, 24)}`;
    const body = {
      v: 1,
      receipt_id,
      ledger_seq: seq,
      ts: new Date().toISOString(),
      decision_code,
      mode,
      agent_id,
      principal_id,
      tool,
      destination: typeof destination === 'string' ? destination.slice(0, 400) : null,
      meta: sanitizeMeta(meta),
      prev_hash: prev,
    };
    const event_hash = hashLine(prev, body);
    body.event_hash = event_hash;

    // Append first so crash after HWM can't "orphan" a seq with Vorgang no event
    // (if crash after append before HWM, next max(line,hwm)+1 still advances cleanly)
    appendFileSync(paths.eventsPath, JSON.stringify(body) + '\n', 'utf8');

    const adv = checkAndAdvanceSoft(seq, paths.hwmPath);
    if (!adv.ok) {
      return {
        ok: false,
        reason: `hwm_or_checkpoint: ${adv.error || 'refused'}`,
      };
    }

    return { ok: true, receipt_id, ledger_seq: seq, event_hash };
  } catch (err) {
    return {
      ok: false,
      reason: err && err.message ? err.message : String(err),
    };
  } finally {
    if (lock && lock.ok && typeof lock.release === 'function') {
      lock.release();
    }
  }
}

/**
 * Verify hash chain + contiguous ledger_seq.
 * @param {string} domainRoot
 */
export function verifyAuditChain(domainRoot) {
  const { eventsPath } = auditPaths(domainRoot);
  if (!existsSync(eventsPath)) return { ok: true, count: 0 };
  const lines = readFileSync(eventsPath, 'utf8').split(/\r?\n/).filter(Boolean);
  let prev = null;
  let prevSeq = 0;
  for (let i = 0; i < lines.length; i++) {
    let row;
    try {
      row = JSON.parse(lines[i]);
    } catch {
      return { ok: false, at: i, reason: 'invalid_json' };
    }
    const { event_hash, ...rest } = row;
    const body = { ...rest };
    const recomputed = hashLine(body.prev_hash || null, body);
    if (recomputed !== event_hash) {
      return { ok: false, at: i, reason: 'hash_mismatch', receipt_id: row.receipt_id };
    }
    if (i > 0 && body.prev_hash !== prev) {
      return { ok: false, at: i, reason: 'prev_hash_break', receipt_id: row.receipt_id };
    }
    if (Number.isInteger(row.ledger_seq)) {
      if (i === 0) {
        if (row.ledger_seq < 1) {
          return { ok: false, at: i, reason: 'seq_invalid', receipt_id: row.receipt_id };
        }
      } else if (row.ledger_seq !== prevSeq + 1) {
        return {
          ok: false,
          at: i,
          reason: 'seq_not_contiguous',
          receipt_id: row.receipt_id,
          expected: prevSeq + 1,
          got: row.ledger_seq,
        };
      }
      prevSeq = row.ledger_seq;
    }
    prev = event_hash;
  }
  return { ok: true, count: lines.length };
}

/**
 * @param {string} domainRoot
 * @param {{ limit?: number, agent_id?: string }} [opts]
 */
export function queryAudit(domainRoot, opts = {}) {
  const { eventsPath } = auditPaths(domainRoot);
  if (!existsSync(eventsPath)) return [];
  const limit = Math.min(Math.max(1, opts.limit || 20), 200);
  const lines = readFileSync(eventsPath, 'utf8').split(/\r?\n/).filter(Boolean);
  const rows = [];
  for (let i = lines.length - 1; i >= 0 && rows.length < limit; i--) {
    try {
      const row = JSON.parse(lines[i]);
      if (opts.agent_id && row.agent_id !== opts.agent_id) continue;
      rows.push({
        receipt_id: row.receipt_id,
        ledger_seq: row.ledger_seq,
        ts: row.ts,
        decision_code: row.decision_code,
        mode: row.mode,
        agent_id: row.agent_id,
        tool: row.tool,
        destination: row.destination,
        event_hash: row.event_hash,
      });
    } catch {
      /* skip */
    }
  }
  return rows;
}
