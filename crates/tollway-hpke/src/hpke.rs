use crate::error::HpkeError;
use crate::format::Enc;
use aead::{AeadCore, AeadInPlace, KeyInit};
use rand_core::CryptoRngCore;
use tollway_primitives::traits::HybridKem;

pub struct Hpke<K: HybridKem, Kdf: KdfAlgorithm, A: AeadCore + AeadInPlace + KeyInit> {
    _phantom: PhantomData<(K, Kdf, A)>,
}

pub struct SenderContext<A: AeadCore + AeadInPlace + KeyInit> {
    pub key: aead::Key<A>,
    pub base_nonce: aead::Nonce<A>,
    pub seq: u64,
}

pub struct RecipientContext<A: AeadCore + AeadInPlace + KeyInit> {
    pub key: aead::Key<A>,
    pub base_nonce: aead::Nonce<A>,
    pub seq: u64,
}

impl<K: HybridKem, Kdf: KdfAlgorithm, A: AeadCore + AeadInPlace + KeyInit> Hpke<K, Kdf, A> {
    // Auth mode setup: sender knows recipient's public key, has own keypair
    pub fn setup_auth_sender(
        recipient_pk: &K::PublicKey,
        sender_sk: &K::SecretKey,
        sender_pk: &K::PublicKey, // Not strictly required if determinable from sk but matches spec API precisely
        info: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Enc, SenderContext<A>), HpkeError> {
        // Will be delegated to mode::auth::setup_auth_sender logic shortly.
        crate::mode::auth::setup_auth_sender::<K, Kdf, A>(
            recipient_pk,
            sender_sk,
            sender_pk,
            info,
            rng,
        )
    }

    pub fn setup_auth_recipient(
        enc: &Enc,
        recipient_sk: &K::SecretKey,
        sender_pk: &K::PublicKey,
        info: &[u8],
    ) -> Result<RecipientContext<A>, HpkeError> {
        // Will be delegated to mode::auth::setup_auth_recipient logic shortly.
        crate::mode::auth::setup_auth_recipient::<K, Kdf, A>(enc, recipient_sk, sender_pk, info)
    }
}
