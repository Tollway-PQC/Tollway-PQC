#![no_main]

use libfuzzer_sys::fuzz_target;
use tollway_primitives::kem::mlkem::{MlKem768, MlKem768Ciphertext, MlKem768SecretKey};
use tollway_primitives::traits::Kem;

fuzz_target!(|data: &[u8]| {
    // The fuzzer feeds arbitrary bytes to decapsulation to verify implicit rejection
    if let Ok(ct) = MlKem768Ciphertext::try_from(data) {
        let sk_bytes = [0u8; 2400];
        if let Ok(sk) = MlKem768SecretKey::try_from(sk_bytes.as_slice()) {
            let _ = MlKem768::decapsulate(&sk, &ct);
        }
    }
});
