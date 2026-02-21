use crate::error::PrimitivesError;
use crate::kem::mlkem::{
    MlKem768, MlKem768Ciphertext, MlKem768PublicKey, MlKem768SecretKey, MlKem768SharedSecret,
};
use crate::kem::x25519::{
    X25519Ciphertext, X25519PublicKey, X25519SecretKey, X25519SharedSecret, X25519,
};
use crate::traits::{HybridKem, Kem};
use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEM_ID_X25519_MLKEM768: u16 = 0xFE30;

pub struct CombinerX25519MlKem768;

#[derive(Clone, Zeroize)]
pub struct HybridPublicKey(pub [u8; 32 + 1184]);

impl AsRef<[u8]> for HybridPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for HybridPublicKey {
    type Error = PrimitivesError;
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 + 1184 {
            return Err(PrimitivesError::InvalidLength);
        }
        let mut arr = [0u8; 32 + 1184];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey(pub [u8; 32 + 2400]);

impl AsRef<[u8]> for HybridSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for HybridSecretKey {
    type Error = PrimitivesError;
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 + 2400 {
            return Err(PrimitivesError::InvalidLength);
        }
        let mut arr = [0u8; 32 + 2400];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

#[derive(Clone)]
pub struct HybridCiphertext(pub [u8; 32 + 1088]);

impl AsRef<[u8]> for HybridCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for HybridCiphertext {
    type Error = PrimitivesError;
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 + 1088 {
            return Err(PrimitivesError::InvalidLength);
        }
        let mut arr = [0u8; 32 + 1088];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret(pub [u8; 32]);

impl AsRef<[u8]> for HybridSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Kem for CombinerX25519MlKem768 {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type Ciphertext = HybridCiphertext;
    type SharedSecret = HybridSharedSecret;
    type Error = PrimitivesError;

    fn generate_keypair(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Self::PublicKey) {
        let (sk1, pk1) = X25519::generate_keypair(rng);
        let (sk2, pk2) = MlKem768::generate_keypair(rng);

        let mut sk = [0u8; 32 + 2400];
        sk[..32].copy_from_slice(sk1.as_ref());
        sk[32..].copy_from_slice(sk2.as_ref());

        let mut pk = [0u8; 32 + 1184];
        pk[..32].copy_from_slice(pk1.as_ref());
        pk[32..].copy_from_slice(pk2.as_ref());

        (HybridSecretKey(sk), HybridPublicKey(pk))
    }

    fn encapsulate(
        pk: &Self::PublicKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        let (pk1, pk2) = pk.0.split_at(32);
        let pk1 = X25519PublicKey::try_from(pk1)?;
        let pk2 = MlKem768PublicKey::try_from(pk2)?;

        let (ct1, mut ss1) = X25519::encapsulate(&pk1, rng)?;
        let (ct2, mut ss2) = MlKem768::encapsulate(&pk2, rng)?;

        let mut ct = [0u8; 32 + 1088];
        ct[..32].copy_from_slice(ct1.as_ref());
        ct[32..].copy_from_slice(ct2.as_ref());

        // Perform the combined HKDF
        let mut ikm = [0u8; 32 + 32 + 32 + 1088];
        let mut offset = 0;
        ikm[offset..offset + 32].copy_from_slice(ss1.as_ref());
        offset += 32;
        ikm[offset..offset + 32].copy_from_slice(ss2.as_ref());
        offset += 32;
        ikm[offset..offset + 32].copy_from_slice(ct1.as_ref());
        offset += 32;
        ikm[offset..offset + 1088].copy_from_slice(ct2.as_ref());

        let (prk, _) = Hkdf::<Sha256>::extract(Some(&[0u8; 32]), &ikm);
        // "The intermediate X25519 and ML-KEM shared secrets must be zeroized immediately"
        // This is handled mechanically via the zeroize-on-drop on ss1 and ss2 and zeroing the bytes buffer
        ikm.zeroize();
        ss1.zeroize();
        ss2.zeroize();

        let mut okm = [0u8; 32];
        // Draft mentions expand with specific label, treating as just extract output size matching SS.
        // Actually, draft says "HKDF-Extract", so we just take prk.
        let mut ss_final = [0u8; 32];
        ss_final.copy_from_slice(&prk[..32]);

        Ok((HybridCiphertext(ct), HybridSharedSecret(ss_final)))
    }

    fn decapsulate(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, Self::Error> {
        let (sk1, sk2) = sk.0.split_at(32);
        let (ct1, ct2) = ct.0.split_at(32);

        let sk1 = X25519SecretKey::try_from(sk1)?;
        let sk2 = MlKem768SecretKey::try_from(sk2)?;
        let ct1 = X25519Ciphertext::try_from(ct1)?;
        let ct2 = MlKem768Ciphertext::try_from(ct2)?;

        let mut ss1 = X25519::decapsulate(&sk1, &ct1)?;
        let mut ss2 = MlKem768::decapsulate(&sk2, &ct2)?;

        let mut ikm = [0u8; 32 + 32 + 32 + 1088];
        let mut offset = 0;
        ikm[offset..offset + 32].copy_from_slice(ss1.as_ref());
        offset += 32;
        ikm[offset..offset + 32].copy_from_slice(ss2.as_ref());
        offset += 32;
        ikm[offset..offset + 32].copy_from_slice(ct1.as_ref());
        offset += 32;
        ikm[offset..offset + 1088].copy_from_slice(ct2.as_ref());

        let (prk, _) = Hkdf::<Sha256>::extract(Some(&[0u8; 32]), &ikm);
        ikm.zeroize();
        ss1.zeroize();
        ss2.zeroize();

        let mut ss_final = [0u8; 32];
        ss_final.copy_from_slice(&prk[..32]);

        Ok(HybridSharedSecret(ss_final))
    }
}

impl HybridKem for CombinerX25519MlKem768 {}
