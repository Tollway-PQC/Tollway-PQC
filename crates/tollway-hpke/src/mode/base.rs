use crate::error::HpkeError;
use crate::format::Enc;
use crate::hpke::{RecipientContext, SenderContext};
use crate::kdf::KdfAlgorithm;
use aead::{AeadCore, AeadInPlace, KeyInit};
use rand_core::CryptoRngCore;
use tollway_primitives::traits::HybridKem;

pub const MODE_BASE: u8 = 0x00;

pub fn setup_base_sender<K: HybridKem, Kdf: KdfAlgorithm, A: AeadCore + AeadInPlace + KeyInit>(
    recipient_pk: &K::PublicKey,
    _info: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(Enc, SenderContext<A>), HpkeError> {
    let (ct, _ss) = K::encapsulate(recipient_pk, rng)?;
    let enc = Enc::new(ct.as_ref());

    // Stubbed key schedule expansion mapping to context object
    let key = aead::Key::<A>::default();
    let base_nonce = aead::Nonce::<A>::default();

    Ok((
        enc,
        SenderContext {
            key,
            base_nonce,
            seq: 0,
        },
    ))
}

pub fn setup_base_recipient<
    K: HybridKem,
    Kdf: KdfAlgorithm,
    A: AeadCore + AeadInPlace + KeyInit,
>(
    _enc: &Enc,
    _recipient_sk: &K::SecretKey,
    _info: &[u8],
) -> Result<RecipientContext<A>, HpkeError> {
    let key = aead::Key::<A>::default();
    let base_nonce = aead::Nonce::<A>::default();
    Ok(RecipientContext {
        key,
        base_nonce,
        seq: 0,
    })
}
