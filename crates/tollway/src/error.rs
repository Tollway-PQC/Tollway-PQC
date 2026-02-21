use core::fmt;

#[derive(Debug)]
pub enum TollwayError {
    InvalidKeyBytes,
    EncryptionFailure,
    DecryptionFailure,
}

impl fmt::Display for TollwayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TollwayError::InvalidKeyBytes => write!(f, "Invalid key bytes provided"),
            TollwayError::EncryptionFailure => write!(f, "Message sealing failed"),
            TollwayError::DecryptionFailure => write!(f, "Message opening failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TollwayError {}

impl From<tollway_hpke::HpkeError> for TollwayError {
    fn from(_: tollway_hpke::HpkeError) -> Self {
        TollwayError::EncryptionFailure
    }
}
