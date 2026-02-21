#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[derive(Clone)]
pub struct Enc {
    #[cfg(feature = "alloc")]
    bytes: Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    bytes: [u8; 1120], // Core hybrid enc length representing X25519 ephemeral pk (32) and ML-KEM-768 (1088)
}

impl Enc {
    #[cfg(feature = "alloc")]
    pub fn new(data: &[u8]) -> Self {
        Self {
            bytes: data.to_vec(),
        }
    }

    #[cfg(not(feature = "alloc"))]
    pub fn new(data: &[u8]) -> Self {
        let mut bytes = [0u8; 1120];
        if data.len() == 1120 {
            bytes.copy_from_slice(data);
        }
        Self { bytes }
    }

    pub fn to_bytes(&self) -> &[u8] {
        #[cfg(feature = "alloc")]
        return &self.bytes;
        #[cfg(not(feature = "alloc"))]
        return &self.bytes;
    }
}
