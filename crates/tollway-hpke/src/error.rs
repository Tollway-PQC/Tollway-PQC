use core::fmt;

#[derive(Debug)]
pub enum HpkeError {
    InvalidCiphertext,
    DecapsulationError,
    KdfError,
    AeadError,
    InvalidKeyLength,
    InvalidMode,
    BufferTooSmall,
}

impl fmt::Display for HpkeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HpkeError::InvalidCiphertext => write!(f, "invalid ciphertext format or tag"),
            HpkeError::DecapsulationError => write!(f, "KEM decapsulation failed"),
            HpkeError::KdfError => write!(f, "Key derivation failed"),
            HpkeError::AeadError => write!(f, "AEAD encryption/decryption failed"),
            HpkeError::InvalidKeyLength => write!(f, "invalid key length provided"),
            HpkeError::InvalidMode => write!(f, "invalid HPKE mode specified"),
            HpkeError::BufferTooSmall => write!(f, "internal buffer capacity exceeded"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HpkeError {}

impl From<tollway_primitives::error::PrimitivesError> for HpkeError {
    fn from(_: tollway_primitives::error::PrimitivesError) -> Self {
        HpkeError::DecapsulationError
    }
}
