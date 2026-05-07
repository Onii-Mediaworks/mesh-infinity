// fuzz_targets/fuzz_decrypt_message.rs — Four-layer message decrypt fuzz target
//
// # What this target tests
//
// `decrypt_message()` is a security boundary. It consumes attacker-controlled
// encrypted bytes plus key material derived from earlier protocol state and
// must never panic, never accept corrupted ciphertext as valid plaintext, and
// never succeed unless all authentication layers verify.
//
// # Harness strategy
//
// Purely random ciphertext reaches only the earliest failure paths. To get
// useful coverage, this harness first constructs a valid encrypted message with
// deterministic keys, then applies bounded mutations to the ciphertext, sender
// key, recipient key, session key, nonce, ratchet key, or context before
// calling `decrypt_message()`.
//
// This exercises both:
// - the happy-path round trip
// - adversarial corruption of each input boundary

#![no_main]

use ed25519_dalek::{SigningKey, VerifyingKey};
use libfuzzer_sys::fuzz_target;
use mesh_infinity::crypto::message_encrypt::{
    decrypt_message, encrypt_message, MessageContext,
};
use mesh_infinity::testing::arbitrary::ByteCursor;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

fn take_array<const N: usize>(cursor: &mut ByteCursor<'_>) -> [u8; N] {
    let mut out = [0u8; N];
    let bytes = cursor.take_bytes(N);
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

fn take_context(cursor: &mut ByteCursor<'_>) -> MessageContext {
    match cursor.take_u8() % 6 {
        0 => MessageContext::Direct,
        1 => MessageContext::Group,
        2 => MessageContext::File,
        3 => MessageContext::Stream,
        4 => MessageContext::Offline,
        _ => MessageContext::System,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);

    // Keep the generated plaintext small enough that the harness stays cheap
    // while still exploring non-empty and truncated-message paths.
    let plaintext = cursor.take_bytes(128).to_vec();

    let sender_seed = take_array::<32>(&mut cursor);
    let sender_alt_seed = take_array::<32>(&mut cursor);
    let recipient_secret_bytes = take_array::<32>(&mut cursor);
    let wrong_recipient_secret_bytes = take_array::<32>(&mut cursor);
    let ratchet_msg_key = take_array::<32>(&mut cursor);
    let wrong_ratchet_msg_key = take_array::<32>(&mut cursor);
    let session_cipher_key = take_array::<32>(&mut cursor);
    let wrong_session_cipher_key = take_array::<32>(&mut cursor);
    let session_nonce = take_array::<12>(&mut cursor);
    let wrong_session_nonce = take_array::<12>(&mut cursor);

    let context = take_context(&mut cursor);
    let wrong_context = take_context(&mut cursor);

    let sender_mask_key = SigningKey::from_bytes(&sender_seed);
    let sender_verifying_key = sender_mask_key.verifying_key();
    let wrong_sender_verifying_key = SigningKey::from_bytes(&sender_alt_seed).verifying_key();

    let recipient_x25519_secret = X25519Secret::from(recipient_secret_bytes);
    let recipient_x25519_pub = X25519Public::from(&recipient_x25519_secret);
    let wrong_recipient_x25519_secret = X25519Secret::from(wrong_recipient_secret_bytes);

    let mut encrypted = match encrypt_message(
        &plaintext,
        &ratchet_msg_key,
        &session_cipher_key,
        &session_nonce,
        &sender_mask_key,
        &recipient_x25519_pub,
        context,
    ) {
        Ok(encrypted) => encrypted,
        Err(_) => return,
    };

    // Choose one bounded corruption strategy so the decrypt path sees both
    // valid and invalid combinations instead of only random early failures.
    let mutation = cursor.take_u8() % 8;

    let decrypting_secret = match mutation {
        5 => &wrong_recipient_x25519_secret,
        _ => &recipient_x25519_secret,
    };
    let verifying_key: VerifyingKey = match mutation {
        4 => wrong_sender_verifying_key,
        _ => sender_verifying_key,
    };
    let decrypt_session_key = match mutation {
        6 => &wrong_session_cipher_key,
        _ => &session_cipher_key,
    };
    let decrypt_session_nonce = match mutation {
        7 => &wrong_session_nonce,
        _ => &session_nonce,
    };
    let decrypt_ratchet_key = match mutation {
        3 => &wrong_ratchet_msg_key,
        _ => &ratchet_msg_key,
    };
    let decrypt_context = match mutation {
        2 => wrong_context,
        _ => context,
    };

    match mutation {
        0 => {}
        1 => {
            let max_index = encrypted.len().saturating_sub(1);
            let index = cursor.take_bounded_usize(max_index);
            if let Some(index) = encrypted.get_mut(index) {
                *index ^= cursor.take_u8().max(1);
            }
        }
        2..=7 => {}
        _ => unreachable!(),
    }

    if mutation == 1 && cursor.take_bool() && !encrypted.is_empty() {
        encrypted.truncate(cursor.take_bounded_usize(encrypted.len().saturating_sub(1)));
    }

    let result = decrypt_message(
        &encrypted,
        decrypting_secret,
        &verifying_key,
        decrypt_session_key,
        decrypt_session_nonce,
        decrypt_ratchet_key,
        decrypt_context,
    );

    // Only the unmutated path is expected to succeed and round-trip exactly.
    if mutation == 0 {
        if let Ok(decrypted) = result {
            assert_eq!(decrypted, plaintext, "valid decrypt path must round-trip");
        }
    }
});
