#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod error;

pub use error::TollwayError as Error;

pub struct PublicKey(pub [u8; 1184 + 32]);
pub struct SecretKey(pub [u8; 2400 + 32]);

#[cfg(feature = "alloc")]
pub struct Ciphertext(pub alloc::vec::Vec<u8>);

#[cfg(not(feature = "alloc"))]
pub struct Ciphertext(pub [u8; 1184]); // Simplified stub size lacking AEAD tag length bound statically

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 1184 + 32 {
            return Err(Error::InvalidKeyBytes);
        }
        let mut arr = [0u8; 1184 + 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SecretKey {
    pub fn generate() -> (Self, PublicKey) {
        // stub generator bridging primitives.
        (SecretKey([0u8; 2400 + 32]), PublicKey([0u8; 1184 + 32]))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 2400 + 32 {
            return Err(Error::InvalidKeyBytes);
        }
        let mut arr = [0u8; 2400 + 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

#[cfg(feature = "alloc")]
pub fn seal(
    _plaintext: &[u8],
    _sender_sk: &SecretKey,
    _recipient_pk: &PublicKey,
) -> Result<Ciphertext, Error> {
    Ok(Ciphertext(alloc::vec::Vec::new()))
}

#[cfg(feature = "alloc")]
pub fn open(
    _ciphertext: &Ciphertext,
    _recipient_sk: &SecretKey,
    _sender_pk: &PublicKey,
) -> Result<alloc::vec::Vec<u8>, Error> {
    Ok(alloc::vec::Vec::new())
}
