#![no_main]

use libfuzzer_sys::fuzz_target;
use tollway_hpke::format::Enc;

fuzz_target!(|data: &[u8]| {
    // The fuzzer verifies wire parsing robustness
    let _enc = Enc::new(data);
});
