// SSOT freeze presence + closed codes (TASK-KS-E-001/002)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { closedSet } from '../core/decision-codes.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

test('ssot tool-menu and decision-codes exist', () => {
  assert.ok(existsSync(join(ROOT, 'ssot', 'tool-menu.json')));
  assert.ok(existsSync(join(ROOT, 'ssot', 'decision-codes.json')));
  assert.ok(existsSync(join(ROOT, 'ssot', 'ladder-l0-l3.md')));
  const menu = JSON.parse(readFileSync(join(ROOT, 'ssot', 'tool-menu.json'), 'utf8'));
  const tier1 = menu.tiers.tier1_governed.tools.map((t) => t.name);
  assert.ok(tier1.includes('kc_route'));
  assert.ok(tier1.includes('kc_bundle'));
  assert.ok(tier1.includes('kc_policy_check'));
});

test('mcp/server.mjs registers DEC-108 tier1 tools', () => {
  const src = readFileSync(join(ROOT, 'mcp', 'server.mjs'), 'utf8');
  for (const t of ['kc_route', 'kc_bundle', 'kc_policy_check', 'kc_search']) {
    assert.ok(src.includes(`registerTool("${t}"`), `missing ${t}`);
  }
  assert.ok(src.includes('createModeBDoor'));
  assert.ok(closedSet().length >= 10);
});
