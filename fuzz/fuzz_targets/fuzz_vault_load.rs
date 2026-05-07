// fuzz_targets/fuzz_vault_load.rs — Vault blob decode fuzz target (§17.9,
// §21.1.3)
//
// # What this target tests
//
// Vault files are attacker-controlled bytes once the filesystem or backup
// medium is considered hostile. Loading must reject short headers, unknown
// schema versions, tampered ciphertext, wrong-key decrypts, and malformed JSON
// without panicking or partially accepting state.
//
// # Harness strategy
//
// 1. Feed arbitrary bytes directly into `VaultCollection::decode_bytes()`.
// 2. Build a valid encrypted vault blob with `encode_bytes()`.
// 3. Apply bounded mutations to the schema header, nonce/ciphertext, or key
//    and re-run `decode_bytes()`.

#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use mesh_infinity::storage::vault::VaultCollection;
use mesh_infinity::testing::arbitrary::ByteCursor;

fn take_array<const N: usize>(cursor: &mut ByteCursor<'_>) -> [u8; N] {
    let mut out = [0u8; N];
    let bytes = cursor.take_bytes(N);
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);
    let master_key = take_array::<32>(&mut cursor);
    let wrong_master_key = take_array::<32>(&mut cursor);

    let vault = match VaultCollection::new(Path::new("."), "fuzz", &master_key) {
        Ok(vault) => vault,
        Err(_) => return,
    };

    let value = String::from_utf8_lossy(cursor.take_bytes(128)).to_string();

    let _ = vault.decode_bytes::<String>(data);

    let mut encoded = match vault.encode_bytes(&value) {
        Ok(encoded) => encoded,
        Err(_) => return,
    };

    match cursor.take_u8() % 6 {
        0 => {}
        1 => {
            encoded.truncate(cursor.take_bounded_usize(encoded.len().saturating_sub(1)));
        }
        2 => {
            if let Some(version) = encoded.get_mut(0) {
                *version = version.saturating_add(1).max(2);
            }
        }
        3 => {
            if !encoded.is_empty() {
                let index = cursor.take_bounded_usize(encoded.len().saturating_sub(1));
                if let Some(byte) = encoded.get_mut(index) {
                    *byte ^= cursor.take_u8().max(1);
                }
            }
        }
        4 => {
            encoded.extend_from_slice(cursor.take_bytes(32));
        }
        5 => {}
        _ => unreachable!(),
    }

    let decode_vault = if cursor.take_u8() % 6 == 5 {
        match VaultCollection::new(Path::new("."), "fuzz", &wrong_master_key) {
            Ok(vault) => vault,
            Err(_) => return,
        }
    } else {
        vault
    };

    let result = decode_vault.decode_bytes::<String>(&encoded);
    if cursor.take_u8() % 6 == 0 {
        if let Ok(decoded) = result {
            assert_eq!(decoded, value, "unmutated vault blob must round-trip");
        }
    }
});
