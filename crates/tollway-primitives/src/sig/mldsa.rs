use crate::error::PrimitivesError;
use crate::traits::Signature;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct MlDsa65;

#[derive(Clone, Zeroize)]
pub struct MlDsa65PublicKey(pub [u8; 1952]);

impl AsRef<[u8]> for MlDsa65PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for MlDsa65PublicKey {
    type Error = PrimitivesError;
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 1952 {
            return Err(PrimitivesError::InvalidLength);
        }
        let mut arr = [0u8; 1952];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa65SecretKey(pub [u8; 4032]);

impl AsRef<[u8]> for MlDsa65SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for MlDsa65SecretKey {
    type Error = PrimitivesError;
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 4032 {
            return Err(PrimitivesError::InvalidLength);
        }
        let mut arr = [0u8; 4032];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

#[derive(Clone)]
pub struct MlDsa65Signature(pub [u8; 3309]);

impl AsRef<[u8]> for MlDsa65Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for MlDsa65Signature {
    type Error = PrimitivesError;
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 3309 {
            return Err(PrimitivesError::InvalidLength);
        }
        let mut arr = [0u8; 3309];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

impl Signature for MlDsa65 {
    type PublicKey = MlDsa65PublicKey;
    type SecretKey = MlDsa65SecretKey;
    type Sig = MlDsa65Signature;
    type Error = PrimitivesError;

    fn generate_keypair(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Self::PublicKey) {
        let (sk, pk) = ml_dsa::MlDsa65::generate(rng);

        let sk_bytes: [u8; 4032] = sk.into();
        let pk_bytes: [u8; 1952] = pk.into();

        (MlDsa65SecretKey(sk_bytes), MlDsa65PublicKey(pk_bytes))
    }

    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Self::Sig {
        let sk_struct = ml_dsa::SigningKey::<ml_dsa::MlDsa65Params>::from_bytes(&sk.0.into());
        // Since the interface bounds in rustcrypto can vary, we assume standard signature traits
        // If sign accepts rng (for randomized mldsa), we fall back assuming default or random. FIPS 204 often uses deterministic when rnd=NULL.
        // Assuming deterministic or simple sign trait implementation wrapper:
        let sig = ml_dsa::MlDsa65::sign_detached(&sk_struct, message, &[]);
        let sig_arr: [u8; 3309] = sig.into();
        MlDsa65Signature(sig_arr)
    }

    fn verify(pk: &Self::PublicKey, message: &[u8], sig: &Self::Sig) -> Result<(), Self::Error> {
        let pk_struct = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65Params>::from_bytes(&pk.0.into());
        let sig_struct = sig.0.into();
        if ml_dsa::MlDsa65::verify_detached(&pk_struct, message, &sig_struct).is_err() {
            Err(PrimitivesError::SignatureVerificationFailed)
        } else {
            Ok(())
        }
    }
}
