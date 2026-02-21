#![no_main]

use libfuzzer_sys::fuzz_target;
use tollway::open;
use tollway::{Ciphertext, PublicKey, SecretKey};

fuzz_target!(|data: &[u8]| {
    // The fuzzer feeds arbitrary bytes as ciphertext to open()
    // It must not panic and must safely return Err.
    let sk_bytes = [0u8; 2432];
    let pk_bytes = [0u8; 1216];

    if let (Ok(sk), Ok(pk)) = (
        SecretKey::from_bytes(&sk_bytes),
        PublicKey::from_bytes(&pk_bytes),
    ) {
        #[cfg(feature = "alloc")]
        {
            let ct = Ciphertext(data.to_vec());
            let _ = open(&ct, &sk, &pk);
        }
    }
});
