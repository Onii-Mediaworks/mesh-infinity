# Offline bundle: attacker-controlled `packet_count` drove `Vec::with_capacity`

Target: fuzz_offline_bundle_decode

## What the input triggers

`input.bin` is a correctly sealed encrypted offline bundle (§5.28) for the
deterministic recipient secret `0x11 * 32` (the first 32 bytes of the input,
per the fuzz target's layout).  The AEAD tag verifies, so the inner plaintext
reaches `transport::offline::parse_bundle`.  The inner header is valid except
that `packet_count` is `0xFFFF_FFFF` while the body holds a single 3-byte
packet.

## Affected parser

`backend/transport/offline.rs::parse_bundle` sized its packet vector from the
header field before validating it:

```rust
let mut packets: Vec<Vec<u8>> = Vec::with_capacity(header.packet_count as usize);
```

`u32::MAX * 24` bytes (~96 GiB) is unsatisfiable, so the allocator aborted the
importing process (`handle_alloc_error`) — on a QR/USB/SD import, a crash of
the whole app from a bundle anyone can craft with the recipient's public key.

## Security relevance

Yes: remote-triggerable process abort (denial of service) at an external byte
boundary, reachable through `mi_import_offline_bundle`.

## Coverage now

- `parse_bundle` bounds `packet_count` against `MAX_BUNDLE_PACKETS` and the
  body length, and requires `total_size` to account for the body exactly,
  before any allocation.
- Unit tests: `transport::offline::tests::bundle_rejects_packet_count_u32_max`
  and friends; `transport::offline_bundle::tests::open_rejects_inner_packet_count_u32_max`.
- Corpus replay: `fuzz/corpus/fuzz_offline_bundle_decode/seed_02_packet_count_u32_max`
  (same bytes as `input.bin`) is replayed by
  `transport::offline_bundle::tests::offline_bundle_corpus_replay`, which
  asserts the seed decrypts and stops at `OfflineError::TooManyPackets`.
