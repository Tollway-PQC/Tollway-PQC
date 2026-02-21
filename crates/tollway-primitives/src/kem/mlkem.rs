use crate::error::PrimitivesError;
use crate::traits::Kem;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct MlKem768;

#[derive(Clone, Zeroize)]
pub struct MlKem768PublicKey(pub [u8; 1184]);

impl AsRef<[u8]> for MlKem768PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for MlKem768PublicKey {
    type Error = PrimitivesError;
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 1184 {
            return Err(PrimitivesError::InvalidLength);
        }
        let mut arr = [0u8; 1184];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem768SecretKey(pub [u8; 2400]);

impl AsRef<[u8]> for MlKem768SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for MlKem768SecretKey {
    type Error = PrimitivesError;
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 2400 {
            return Err(PrimitivesError::InvalidLength);
        }
        let mut arr = [0u8; 2400];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

#[derive(Clone)]
pub struct MlKem768Ciphertext(pub [u8; 1088]);

impl AsRef<[u8]> for MlKem768Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for MlKem768Ciphertext {
    type Error = PrimitivesError;
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 1088 {
            return Err(PrimitivesError::InvalidLength);
        }
        let mut arr = [0u8; 1088];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem768SharedSecret(pub [u8; 32]);

impl AsRef<[u8]> for MlKem768SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Kem for MlKem768 {
    type PublicKey = MlKem768PublicKey;
    type SecretKey = MlKem768SecretKey;
    type Ciphertext = MlKem768Ciphertext;
    type SharedSecret = MlKem768SharedSecret;
    type Error = PrimitivesError;

    fn generate_keypair(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Self::PublicKey) {
        // Assume ml_kem::MlKem768::generate roughly has this shape, we will verify.
        let (dk, ek) = ml_kem::MlKem768::generate(rng);

        // Use into / clone methods to map to primitive arrays natively
        let dk_bytes: [u8; 2400] = dk.into();
        let ek_bytes: [u8; 1184] = ek.into();

        (MlKem768SecretKey(dk_bytes), MlKem768PublicKey(ek_bytes))
    }

    fn encapsulate(
        pk: &Self::PublicKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        // Will be corrected against specific rustcrypto api
        let pk_struct =
            ml_kem::kem::EncapsulatingKey::<ml_kem::MlKem768Params>::from_bytes(&pk.0.into());
        let (ct, ss) = ml_kem::MlKem768::encapsulate(&pk_struct, rng);
        let ct_arr: [u8; 1088] = ct.into();
        let ss_arr: [u8; 32] = ss.into();
        Ok((MlKem768Ciphertext(ct_arr), MlKem768SharedSecret(ss_arr)))
    }

    fn decapsulate(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, Self::Error> {
        let sk_struct =
            ml_kem::kem::DecapsulatingKey::<ml_kem::MlKem768Params>::from_bytes(&sk.0.into());
        let ct_arr = ct.0.into();
        let ss = ml_kem::MlKem768::decapsulate(&sk_struct, &ct_arr);
        let ss_arr: [u8; 32] = ss.into();
        Ok(MlKem768SharedSecret(ss_arr))
    }
}
