#!/usr/bin/env node
// KnoSky CI3 — GitHub Action glue (KSV2-CI3). Runs knoskyCi() to produce the
// route/safety artifacts, renders the claims-disciplined comment body via
// renderPrComment(), then upserts (creates or updates) ONE PR comment via the
// GitHub REST API using the caller-supplied token.
//
// HARD RULE (matches ci.mjs / D-162 claims discipline): this script must NEVER
// fail the consumer's build on an internal error. The only way this process
// exits non-zero is `fail-on-secret: true` AND knoskyCi() actually finding a
// secret-like pattern in the emitted artifacts — everything else is caught and
// logged, never thrown past main().
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORE = path.resolve(HERE, '..', 'core');
const MARKER = '<!-- knosky-pr-gps -->';

async function ghFetch(token, url, opts = {}) {
  const res = await fetch(url, {
    ...opts,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(opts.headers || {}),
    },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`GitHub API ${opts.method || 'GET'} ${url} -> ${res.status}: ${text.slice(0, 300)}`);
  }
  return res.status === 204 ? null : res.json();
}

async function upsertComment({ token, repo, prNumber, body }) {
  const base = `https://api.github.com/repos/${repo}/issues/${prNumber}/comments`;
  const existing = await ghFetch(token, `${base}?per_page=100`);
  const mine = Array.isArray(existing)
    ? existing.find((c) => typeof c.body === 'string' && c.body.includes(MARKER))
    : null;
  if (mine) {
    await ghFetch(token, `https://api.github.com/repos/${repo}/issues/comments/${mine.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ body }),
    });
    console.log('KnoSky action: updated the existing PR-GPS comment.');
  } else {
    await ghFetch(token, base, { method: 'POST', body: JSON.stringify({ body }) });
    console.log('KnoSky action: posted a new PR-GPS comment.');
  }
}

async function main() {
  const env = process.env;
  const token = env.GITHUB_TOKEN;
  const repo = env.KC_REPO || '';
  const prNumber = env.KC_PR_NUMBER || '';

  const { knoskyCi } = await import(path.join(CORE, 'ci.mjs'));
  const { renderPrComment } = await import(path.join(CORE, 'pr-comment.mjs'));

  const { exitCode, routeJson, safetyJson } = await knoskyCi({
    root: env.KC_ROOT || '.',
    base: env.KC_BASE,
    head: env.KC_HEAD,
    cityPath: env.KC_CITY,
    failOnSecret: env.KC_FAIL_ON_SECRET === 'true',
  });

  if (!token || !repo || !prNumber) {
    // Not a pull_request context (or the caller didn't wire the inputs) —
    // nothing to comment on. Advisory tool, nothing to do, exit clean.
    console.log('KnoSky action: no PR context (repo/PR number/token missing) — skipping the comment.');
    return exitCode;
  }

  const body = MARKER + '\n' + renderPrComment({ routeJson, safetyJson });
  await upsertComment({ token, repo, prNumber, body });

  return exitCode;
}

main()
  .then((code) => { process.exitCode = code || 0; })
  .catch((err) => {
    console.error('KnoSky action: internal error (advisory-only — not failing the build):', err && err.message);
    process.exitCode = 0;
  });
