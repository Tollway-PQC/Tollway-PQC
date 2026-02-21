use crate::bundle::PrekeyBundle;
use crate::error::PqxdhError;
use rand_core::CryptoRngCore;

pub struct PqxdhInitiator;
pub struct PqxdhResponder;

pub struct InitialMessage {
    pub ephemeral_key: [u8; 32],
    pub kem_ciphertext: [u8; 1088],
}

pub struct IdentityKeys {
    pub identity_key: [u8; 32], // Secret scalar for X25519
}

impl PqxdhInitiator {
    pub fn initiate(
        _bundle: &PrekeyBundle,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(InitialMessage, [u8; 32]), PqxdhError> {
        // Stub for skeleton
        Ok((
            InitialMessage {
                ephemeral_key: [0u8; 32],
                kem_ciphertext: [0u8; 1088],
            },
            [0u8; 32],
        ))
    }
}

impl PqxdhResponder {
    pub fn respond(
        _msg: &InitialMessage,
        _identity: &IdentityKeys,
    ) -> Result<[u8; 32], PqxdhError> {
        // Stub for skeleton
        Ok([0u8; 32])
    }
}
