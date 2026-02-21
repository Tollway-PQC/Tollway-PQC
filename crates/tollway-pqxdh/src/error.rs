use core::fmt;

#[derive(Debug)]
pub enum PqxdhError {
    InvalidBundle,
    DecapsulationFailed,
    KeyDerivationFailed,
}

impl fmt::Display for PqxdhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PqxdhError::InvalidBundle => write!(f, "provided prekey bundle is invalid"),
            PqxdhError::DecapsulationFailed => write!(f, "Failed to decapsulate KEM payload"),
            PqxdhError::KeyDerivationFailed => write!(f, "Failed to derive PQXDH schedule"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PqxdhError {}
