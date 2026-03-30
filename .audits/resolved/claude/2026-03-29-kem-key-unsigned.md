## Resolution Status: RESOLVED
# ML-KEM-768 Encapsulation Key Not Signed by Ed25519 Identity Key — PQ Downgrade Attack
**Date:** 2026-03-29
**Auditor:** claude-sonnet-4-6
**Status:** UNRESOLVED
**Severity:** High

## Issue

`backend/identity/self_identity.rs:109–111` derives the ML-KEM-768 keypair deterministically
from `master_key`. The `kem_encapsulation_key` is advertised in network map gossip
(`backend/network/map.rs:83`) and pairing payloads.

Unlike the preauth X25519 key (which has a `preauth_sig` field in `PreauthBundle`
verified at `backend/crypto/x3dh.rs:203–219` against the Ed25519 identity key), the
ML-KEM-768 encapsulation key has NO Ed25519 signature binding it to the identity.

An active on-path attacker can:
1. Intercept a gossip map entry containing `kem_encapsulation_key`.
2. Strip or substitute the KEM encapsulation key with their own.
3. Alice uses the attacker's KEM key for encapsulation in PQXDH.
4. The attacker decapsulates and recovers `pq_ss`, mixing it into the master_secret.
5. If classical X25519 is later compromised, the "post-quantum" protection is already gone.

The protocol claims post-quantum forward secrecy (§3.4.1) but allows silent PQ downgrade
by key substitution.

## Resolution
*(fill in when resolved)*

Add a `kem_sig: Option<Vec<u8>>` field to `PreauthBundle` (x3dh.rs) containing an
Ed25519 signature over `"MeshInfinity_PQXDH_kem_pub_v1" || kem_encapsulation_key_bytes`
signed by the identity Ed25519 key. Verify this signature in `x3dh_initiate()` the same
way `preauth_sig` is verified. Generate the signature alongside the KEM keypair in
`self_identity.rs`. Include it in gossip map `PublicKeyRecord` as `kem_sig: Option<Vec<u8>>`.
