## Resolution Status: RESOLVED
# Insufficient Validation in Backup Key Derivation

**Date:** 2026-03-30
**Auditor:** openrouter
**Status:** UNRESOLVED
**Severity:** Medium

## Issue
In `backend/crypto/backup.rs`, the backup key derivation does not enforce maximum iteration limits beyond `MIN_T_COST`. Weak passphrases could be brute-forced if Argon2 parameters are downgraded or if an attacker can control the configuration.

## Location
File: `backend/crypto/backup.rs`
Functions: `derive_backup_key`, `create_backup`, `restore_backup`

## Current Implementation
The code uses Argon2id with minimum cost parameters (`MIN_M_COST`, `MIN_T_COST`, `MIN_P_COST`) but does not validate that the actual parameters used are within secure bounds. There's no upper bound check to prevent downgrade attacks or ensure sufficient computational cost.

## Risk
- Brute-force attacks on weak passphrases could be accelerated if Argon2 parameters are reduced
- Lack of upper bounds could lead to DoS through excessive resource consumption
- Inconsistent security across different backup operations

## Recommendation
1. Add validation in `derive_backup_key` to ensure:
   - `t_cost` does not exceed a reasonable maximum (e.g., 10x `MIN_T_COST`)
   - `p_cost` does not exceed a reasonable maximum (e.g., 10x `MIN_P_COST`)
   - `m_cost` does not exceed platform-specific limits
2. Reject backup creation or restoration if parameters fall outside secure ranges
3. Log warnings when non-default parameters are used
4. Consider making the cost parameters part of the backup format to detect tampering

## References
- SPEC.md §3.7.4 (Backup, Restore, and Safety Numbers)
- Argon2id RFC 9106
- Password hashing best practices