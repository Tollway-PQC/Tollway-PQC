use crate::error::PrimitivesError;
use crate::traits::Kem;
use rand_core::CryptoRngCore;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct X25519;

#[derive(Clone, Zeroize)]
pub struct X25519PublicKey(pub [u8; 32]);

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for X25519PublicKey {
    type Error = PrimitivesError;
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(PrimitivesError::InvalidLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519SecretKey(pub [u8; 32]);

impl AsRef<[u8]> for X25519SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for X25519SecretKey {
    type Error = PrimitivesError;
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(PrimitivesError::InvalidLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

#[derive(Clone)]
pub struct X25519Ciphertext(pub [u8; 32]);

impl AsRef<[u8]> for X25519Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for X25519Ciphertext {
    type Error = PrimitivesError;
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(PrimitivesError::InvalidLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519SharedSecret(pub [u8; 32]);

impl AsRef<[u8]> for X25519SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Kem for X25519 {
    type PublicKey = X25519PublicKey;
    type SecretKey = X25519SecretKey;
    type Ciphertext = X25519Ciphertext;
    type SharedSecret = X25519SharedSecret;
    type Error = PrimitivesError;

    fn generate_keypair(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Self::PublicKey) {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let sk = StaticSecret::from(bytes);
        let pk = PublicKey::from(&sk);
        (
            X25519SecretKey(sk.to_bytes()),
            X25519PublicKey(pk.to_bytes()),
        )
    }

    fn encapsulate(
        pk: &Self::PublicKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let our_sk = EphemeralSecret::random_from_rng(rng);
        let our_pk = PublicKey::from(&our_sk);
        let their_pk = PublicKey::from(pk.0);
        let ss = our_sk.diffie_hellman(&their_pk);
        Ok((
            X25519Ciphertext(our_pk.to_bytes()),
            X25519SharedSecret(ss.to_bytes()),
        ))
    }

    fn decapsulate(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, Self::Error> {
        let our_sk = StaticSecret::from(sk.0);
        let their_pk = PublicKey::from(ct.0);
        let ss = our_sk.diffie_hellman(&their_pk);
        Ok(X25519SharedSecret(ss.to_bytes()))
    }
}
