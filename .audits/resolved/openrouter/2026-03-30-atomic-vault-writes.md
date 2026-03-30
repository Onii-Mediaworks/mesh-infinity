## Resolution Status: RESOLVED

# Non-Atomic Vault File Writes

**Date:** 2026-03-30
**Auditor:** openrouter
**Status:** UNRESOLVED
**Severity:** Medium

## Issue
In `backend/storage/vault.rs`, vault file writes are not guaranteed to be atomic. If a write operation is interrupted (e.g., power loss, crash, kill signal), the vault file could be left in a partially written state, leading to data corruption or loss.

## Location
File: `backend/storage/vault.rs`
Functions: `VaultCollection::save`, `VaultManager::save_collection`

## Current Implementation
The code writes directly to the vault file without using a temporary file and rename pattern, which is the standard approach for atomic writes.

## Risk
- Vault corruption if write is interrupted
- Loss of encrypted data (messages, contacts, settings)
- Potential for inconsistent state across application restarts
- May require manual recovery or data re-entry

## Recommendation
1. Implement atomic write pattern:
   - Write to a temporary file (e.g., `collection.vault.tmp`)
   - Flush and sync to disk
   - Rename temporary file to final name (atomic operation on POSIX)
2. Consider using `fsync` or platform-specific sync calls to ensure durability
3. Add checksums or MACs to detect partial writes
4. Implement vault recovery logic that can detect and repair corrupted vaults
5. Add logging for write failures and recovery attempts

## References
- SPEC.md §17.9 (Vault Persistence)
- Atomic file operations best practices
- Data integrity in encrypted storage systems