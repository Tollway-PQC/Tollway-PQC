use tollway_primitives::kem::mlkem::MlKem768PublicKey;
use tollway_primitives::kem::x25519::X25519PublicKey;

pub struct PrekeyBundle {
    pub identity_key: X25519PublicKey,
    pub signed_prekey: X25519PublicKey,
    pub pq_signed_prekey: MlKem768PublicKey,
    pub one_time_prekey: Option<X25519PublicKey>,
}
