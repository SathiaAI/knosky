// KnoSky protocol config tests. Run: node test/config.test.mjs
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DEFAULTS, loadConfig, validateConfig } from '../core/config.mjs';

let failures = 0;
const ok = (name, cond, extra = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' - ' + name + (extra ? '  ' + extra : ''));
  if (!cond) failures++;
};

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'knosky-cfg-')); }

// ---------------------------------------------------------------------------
// (a) No .knosky/config.yml -> loadConfig returns the DEFAULTS values
// ---------------------------------------------------------------------------
{
  const d = tmp();
  const cfg = loadConfig(d);
  ok('no config.yml -> knosky_protocol is "1.0"', cfg.knosky_protocol === '1.0');
  ok('no config.yml -> telemetry is false', cfg.telemetry === false);
  ok('no config.yml -> absolute_paths is false', cfg.absolute_paths === false);
  ok('no config.yml -> fail_on_secret is true', cfg.fail_on_secret === true);
  ok('no config.yml -> allow_excerpts is false', cfg.allow_excerpts === false);
  ok('no config.yml -> max_excerpt_chars is 0', cfg.max_excerpt_chars === 0);
  ok('no config.yml -> categories is []', Array.isArray(cfg.categories) && cfg.categories.length === 0);
  ok('no config.yml -> ignore is []', Array.isArray(cfg.ignore) && cfg.ignore.length === 0);
}

// ---------------------------------------------------------------------------
// (b) Sample config.yml flips telemetry, absolute_paths; sets categories
// ---------------------------------------------------------------------------
{
  const d = tmp();
  fs.mkdirSync(path.join(d, '.knosky'));
  fs.writeFileSync(path.join(d, '.knosky', 'config.yml'), [
    '# sample config',
    'knosky_protocol: 1.0',
    'telemetry: true',
    'absolute_paths: true',
    'fail_on_secret: true',
    'allow_excerpts: false',
    'max_excerpt_chars: 0',
    'categories:',
    '  - code',
    '  - docs',
    'ignore:',
    '',
  ].join('\n'));

  const cfg = loadConfig(d);
  ok('sample config -> telemetry is true', cfg.telemetry === true);
  ok('sample config -> absolute_paths is true', cfg.absolute_paths === true);
  ok('sample config -> fail_on_secret stays true', cfg.fail_on_secret === true);
  ok('sample config -> categories has two items', Array.isArray(cfg.categories) && cfg.categories.length === 2, JSON.stringify(cfg.categories));
  ok('sample config -> categories[0] is "code"', cfg.categories[0] === 'code');
  ok('sample config -> categories[1] is "docs"', cfg.categories[1] === 'docs');
  ok('sample config -> ignore is []', Array.isArray(cfg.ignore) && cfg.ignore.length === 0);
  // Defaults not overridden must survive
  ok('sample config -> allow_excerpts remains false', cfg.allow_excerpts === false);
  ok('sample config -> max_excerpt_chars remains 0', cfg.max_excerpt_chars === 0);
}

// ---------------------------------------------------------------------------
// (c) validateConfig(DEFAULTS) -> { ok: true, errors: [] }
// ---------------------------------------------------------------------------
{
  const result = validateConfig(DEFAULTS);
  ok('validateConfig(DEFAULTS) -> ok is true', result.ok === true, JSON.stringify(result.errors));
  ok('validateConfig(DEFAULTS) -> errors is empty', result.errors.length === 0, JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (d) Unknown key + wrong type each produce a validation error
// ---------------------------------------------------------------------------
{
  const badCfg = {
    ...DEFAULTS,
    categories: [],
    ignore: [],
    telemetry: 'yes',       // wrong type: string, not boolean
    mystery_flag: true,     // unknown key
  };
  const result = validateConfig(badCfg);
  ok('invalid config -> ok is false', result.ok === false);
  const hasTypeError = result.errors.some(e => e.includes('telemetry'));
  ok('invalid config -> telemetry type error reported', hasTypeError, JSON.stringify(result.errors));
  const hasUnknownKey = result.errors.some(e => e.includes('mystery_flag'));
  ok('invalid config -> unknown key error reported', hasUnknownKey, JSON.stringify(result.errors));
}

// ---------------------------------------------------------------------------
// (e) Malformed config file makes loadConfig throw
// ---------------------------------------------------------------------------
{
  const d = tmp();
  fs.mkdirSync(path.join(d, '.knosky'));
  fs.writeFileSync(path.join(d, '.knosky', 'config.yml'), '???: [[[not valid yaml at all\n');

  let threw = false;
  try { loadConfig(d); } catch { threw = true; }
  ok('malformed config.yml -> loadConfig throws', threw);
}

console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'all checks passed'));
process.exit(failures ? 1 : 0);
