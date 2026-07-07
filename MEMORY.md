# SAT-583 Implementation Summary

- **Ticket**: SAT-583: SAT-561 follow-up: surface checkpoint-write failures from checkAndAdvance (additive checkpoint_ok)
- **Problem**: Checkpoint-write errors in `checkAndAdvance` were silently swallowed, potentially hiding permanent security checkpoint failures
- **Solution**: Added two new return fields to `checkAndAdvance`:
  - `checkpoint_ok`: boolean | null (true/false for success/failure, null when no checkpointPath supplied)  
  - `checkpoint_error`: string | null (contains error message when checkpoint fails)
- **Files modified**: 
  - `core/ledger.mjs` - updated function signature and implementation
  - `test/ledger.test.mjs` - added SAT-583 test cases
  - `test/append-only-checkpoint.test.mjs` - added SAT-583 test cases
- **Verification**: All existing tests pass + new tests cover the three required scenarios