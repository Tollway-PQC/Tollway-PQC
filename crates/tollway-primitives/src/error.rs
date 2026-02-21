use core::fmt;

#[derive(Debug)]
pub enum PrimitivesError {
    InvalidLength,
    RngError,
    CiphertextVerificationFailed,
    SignatureVerificationFailed,
}

impl fmt::Display for PrimitivesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrimitivesError::InvalidLength => {
                write!(f, "invalid length for cryptographic primitive")
            }
            PrimitivesError::RngError => write!(f, "random number generator failed"),
            PrimitivesError::CiphertextVerificationFailed => {
                write!(f, "ciphertext verification failed (implicit rejection)")
            }
            PrimitivesError::SignatureVerificationFailed => {
                write!(f, "signature verification failed")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrimitivesError {}
