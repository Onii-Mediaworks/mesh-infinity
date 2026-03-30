## Resolution Status: RESOLVED

# LAN Broadcast Exposes Full Mask Identity Keys (§4.9.5 Violation)
**Date:** 2026-03-29
**Auditor:** claude-sonnet-4-6
**Status:** UNRESOLVED
**Severity:** High

## Issue

`backend/ffi/lib.rs:1244–1255` (`advance_lan_discovery`) broadcasts the following
fields in plaintext over UDP to 255.255.255.255:7235 every 5 seconds when LAN discovery
is enabled:

```json
{
  "peer_id": "<hex>",
  "ed25519_pub": "<hex>",
  "x25519_pub": "<hex>",
  "preauth_x25519_pub": "<hex>",
  "preauth_sig": "<hex>",
  "display_name": "<string>",
  "clearnet_port": 7234
}
```

SPEC.md §4.9.5 (line 1925) explicitly states:

> All LAN discovery mechanisms advertise the **mesh identity WireGuard public key**
> (Layer 1) only. **Mask-level keys and peer IDs are never included.**

The broadcast is including `peer_id`, `ed25519_pub`, `x25519_pub`, `preauth_x25519_pub`,
`preauth_sig`, and `display_name` — all Layer 2 (mask-level) material. Any device on
the LAN (AP, corporate monitor, passive sniffer) receives the user's cryptographic
identity and display name in plaintext with no authentication required.

The spec comment at line 1889 says: "It reveals only that a Mesh Infinity node is on
this network segment, not who the user is." The current implementation violates this
property.

## Resolution
*(fill in when resolved)*

Broadcast ONLY the mesh identity WireGuard public key (Layer 1 key, not currently
exposed in the broadcast at all), clearnet port, and version. Remove all mask-level
fields. Update `handle_lan_presence_packet` to only extract endpoint information from
LAN broadcasts; mask-level key exchange must happen via authenticated channels after
out-of-band pairing.
