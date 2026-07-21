// Mode B spine tests (DEC-106/108 residual)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createModeBDoor } from '../core/mode-b.mjs';
import { registerAgentWithLease, loadDomain } from '../core/domain-store.mjs';
import { closedSet, CODES } from '../core/decision-codes.mjs';
import { verifyAuditChain } from '../core/audit-writer.mjs';

function toyCity(dir) {
  const cityPath = join(dir, 'city-data.json');
  const city = {
    node_count: 2,
    nodes: [
      {
        id: 'fs:src/public.js',
        title: 'public',
        summary: 'open helper',
        category: 'src',
        kind: 'file',
        district_class: 'public',
        provenance: { ref: 'src/public.js', source_rev: '1' },
        headings: ['public'],
        tags: ['public'],
      },
      {
        id: 'fs:src/secret.js',
        title: 'secret',
        summary: 'restricted area',
        category: 'src',
        kind: 'file',
        district_class: 'restricted',
        provenance: { ref: 'src/secret.js', source_rev: '1' },
        headings: ['secret'],
        tags: ['auth'],
      },
    ],
    categories: [{ id: 'src', label: 'src', count: 2 }],
  };
  writeFileSync(cityPath, JSON.stringify(city));
  return cityPath;
}

test('closed decision code set includes ALLOW and ADVISORY_UNAUTH', () => {
  const set = closedSet();
  assert.ok(set.includes('ALLOW'));
  assert.ok(set.includes('ADVISORY_UNAUTH'));
  assert.ok(set.includes('DENY_IDENTITY'));
});

test('Mode B DENY_IDENTITY without lease', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-modeb-'));
  try {
    const cityPath = toyCity(dir);
    const domainRoot = join(dir, '.knosky');
    mkdirSync(domainRoot, { recursive: true });
    const { load } = await import('../core/retrieve.mjs');
    const ctx = load(cityPath);
    const door = createModeBDoor({ cityCtx: ctx, cityPath, domainRoot, profile: 'coding' });
    const env = door.handle({ tool: 'route', destination: 'public' });
    assert.equal(env.decision_code, CODES.DENY_IDENTITY);
    assert.equal(env.authorizing, false);
    assert.equal(env.metadata_disclosed, false);
    assert.ok(!env.payload);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Mode B ALLOW with lease + audit receipt', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-modeb-'));
  try {
    const cityPath = toyCity(dir);
    const domainRoot = join(dir, '.knosky');
    const { load } = await import('../core/retrieve.mjs');
    const ctx = load(cityPath);
    const door = createModeBDoor({ cityCtx: ctx, cityPath, domainRoot, profile: 'coding' });
    const reg = registerAgentWithLease(door.domain, {
      agentId: 'agent-alpha',
      classes: ['public', 'internal'],
    });
    assert.equal(reg.ok, true, JSON.stringify(reg));
    const { leaseId, agentId } = reg;
    // reload door domain leases from disk
    const door2 = createModeBDoor({ cityCtx: ctx, cityPath, domainRoot, profile: 'coding' });
    const env = door2.handle({
      tool: 'route',
      destination: 'public',
      leaseId,
      agentId,
    });
    assert.equal(env.decision_code, CODES.ALLOW);
    assert.equal(env.mode, 'B');
    assert.ok(env.receipt_id);
    assert.ok(env.payload);
    assert.equal(env.payload.authorized, true);
    const v = verifyAuditChain(domainRoot);
    assert.equal(v.ok, true);
    assert.ok(v.count >= 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Mode A advisory labels ADVISORY_UNAUTH', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-modeb-'));
  try {
    const cityPath = toyCity(dir);
    const domainRoot = join(dir, '.knosky');
    const { load } = await import('../core/retrieve.mjs');
    const ctx = load(cityPath);
    const door = createModeBDoor({ cityCtx: ctx, cityPath, domainRoot, profile: 'advisory' });
    const env = door.handle({ tool: 'route', destination: 'public' });
    assert.equal(env.decision_code, CODES.ADVISORY_UNAUTH);
    assert.equal(env.mode, 'A');
    assert.equal(env.authorizing, false);
    assert.ok(env.payload);
    assert.equal(env.payload.authorized, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('policy_check returns deterministic envelope', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-modeb-'));
  try {
    const cityPath = toyCity(dir);
    const domainRoot = join(dir, '.knosky');
    const { load } = await import('../core/retrieve.mjs');
    const ctx = load(cityPath);
    const door = createModeBDoor({ cityCtx: ctx, cityPath, domainRoot, profile: 'coding' });
    const reg = registerAgentWithLease(door.domain, {
      agentId: 'agent-beta',
      classes: ['public', 'internal'],
    });
    assert.equal(reg.ok, true, JSON.stringify(reg));
    const { leaseId, agentId } = reg;
    const door2 = createModeBDoor({ cityCtx: ctx, cityPath, domainRoot, profile: 'coding' });
    const env = door2.handle({ tool: 'policy_check', destination: 'public', leaseId, agentId });
    assert.equal(env.decision_code, CODES.ALLOW);
    assert.equal(env.payload.would_allow, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('registerAgentWithLease persists lease store', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ks-dom-'));
  try {
    const domainRoot = join(dir, '.knosky');
    const d = loadDomain(domainRoot);
    const reg = registerAgentWithLease(d, { agentId: 'a1' });
    assert.equal(reg.ok, true, JSON.stringify(reg));
    const { leaseId, agentId } = reg;
    const d2 = loadDomain(domainRoot);
    assert.ok(d2.leaseStore.get(leaseId));
    assert.equal(d2.leaseStore.get(leaseId).agentId, agentId);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
