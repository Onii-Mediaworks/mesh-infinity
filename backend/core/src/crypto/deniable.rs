use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};

use crate::error::Result;

pub struct DeniableAuth {
    identity: Keypair,
}

impl DeniableAuth {
    pub fn new(identity: Keypair) -> Self {
        Self { identity }
    }

    pub fn identity_public_key(&self) -> PublicKey {
        self.identity.public
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.identity.sign(message)
    }

    pub fn verify(
        &self,
        public_key: &PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<bool> {
        Ok(public_key.verify(message, signature).is_ok())
    }
}
