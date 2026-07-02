// Shared, dependency-free constants used by more than one core module.
// Kept in its own file (no imports, no side effects) so any core/*.mjs can
// import from it without creating a circular dependency between modules.

// Upper bound for a plausible ledger sequence (git commit count). 1 billion
// is far beyond any real repo's commit count and far below
// Number.MAX_SAFE_INTEGER (~9e15), so it rejects implausible/attacker-
// supplied values (e.g. 1e100) with no precision-loss risk of its own.
// Enforced independently at two layers — core/freshness.mjs's
// extractLedgerSeq (structural validation) and core/ledger.mjs's
// checkAndAdvance (the persisted guard itself) — both import this single
// source of truth so the two layers cannot silently diverge.
export const MAX_PLAUSIBLE_LEDGER_SEQ = 1_000_000_000;
