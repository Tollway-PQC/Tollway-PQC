use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A Key Encapsulation Mechanism.
pub trait Kem {
    type PublicKey: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]> + Zeroize;
    type SecretKey: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]> + Zeroize + ZeroizeOnDrop;
    type Ciphertext: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;
    type SharedSecret: AsRef<[u8]> + Zeroize + ZeroizeOnDrop;
    type Error: core::fmt::Debug;

    fn generate_keypair(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Self::PublicKey);

    fn encapsulate(
        pk: &Self::PublicKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error>;

    fn decapsulate(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, Self::Error>;
}

/// A Hybrid KEM that combines a classical and post-quantum KEM.
pub trait HybridKem: Kem {}

/// A digital signature scheme.
pub trait Signature {
    type PublicKey;
    type SecretKey;
    type Sig;
    type Error;

    fn generate_keypair(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Self::PublicKey);
    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Self::Sig;
    fn verify(pk: &Self::PublicKey, message: &[u8], sig: &Self::Sig) -> Result<(), Self::Error>;
}
