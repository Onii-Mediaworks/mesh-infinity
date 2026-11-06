// fuzz_targets/fuzz_tunnel_fragment.rs — tunnel fragment reassembly (§12.3)
//
// # What this target tests
//
// `TunnelData` frames arrive from a peer over the mesh session and feed
// `TunnelManager::process_data` / `FragmentReassembler::process`. The
// fragment header (`total_size`, `fragment_index`, `fragment_count`,
// `fragment_id`) and the payload length are attacker-controlled, so the
// reassembler must:
//   - never panic on any header or payload,
//   - never size an allocation from a peer-supplied number,
//   - reject the §12.3 MUST-reject conditions with typed errors,
//   - keep every session under its in-flight cap and byte budget,
//   - evict stale sets instead of letting them pin memory forever.
//
// # Input layout
//
// The whole input is first tried as a JSON `TunnelData` (the serde decode
// boundary), then decoded as a bounded action sequence by the shared
// driver in `services::tunnel::drive_fragment_input`. The in-tree corpus
// replay test uses the same driver, so the committed seeds have one
// meaning everywhere.
//
// # Corpus
//
// `fuzz/corpus/fuzz_tunnel_fragment/` holds a valid two-fragment set, an
// oversized total, an out-of-range index, an over-MTU frame, a duplicate
// followed by a TCP timeout gc, and a frame for an unknown session.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let report = mesh_infinity::services::tunnel::drive_fragment_input(data);
    assert!(
        report.invariants_ok,
        "tunnel fragment reassembly violated a spec bound"
    );
});
