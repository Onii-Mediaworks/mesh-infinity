# Double Ratchet Header in Plaintext Envelope — Traffic Correlation Attack Surface
**Date:** 2026-03-29
**Auditor:** claude-sonnet-4-6
**Status:** UNRESOLVED
**Severity:** High

## Issue

`backend/ffi/lib.rs:5499–5510` builds the wire envelope with `ratchet_pub`,
`prev_chain_len`, and `msg_num` as top-level plaintext JSON fields, outside the
Step 4 recipient encryption:

```json
{
  "ratchet_pub": "<64-char hex>",
  "prev_chain_len": 0,
  "msg_num": 42,
  "ciphertext": "<encrypted blob>"
}
```

A passive observer on clearnet TCP can track `ratchet_pub` transitions to map session
epochs, use `msg_num` to count messages per chain, and use `prev_chain_len` to map
chain boundaries. This enables relationship-graph correlation attacks: two endpoints
sharing the same `ratchet_pub` sequence are definitively communicating.

SPEC.md §7.2 line 4721 places `dr_header` outside Step 4 (`payload = dr_header || trust_encrypted`)
which means the spec itself specifies this behavior. However, §7.2 line 4758 says
"Relay nodes see only the outer encrypted blob and destination address — nothing inside
is visible to them" — the DR header IS visible, which is an inconsistency.

## Resolution
*(fill in when resolved)*

Option A (preferred): Move dr_header inside Step 4 encryption. Change Step 4 input
from `double_signed` to `dr_header || double_signed`. Update SPEC.md §7.2 accordingly.

Option B: Encrypt `ratchet_pub` at the outer frame using the static DH channel key
(already available to both parties post-pairing) so relay nodes see only an encrypted
blob per message, not a trackable key sequence.
