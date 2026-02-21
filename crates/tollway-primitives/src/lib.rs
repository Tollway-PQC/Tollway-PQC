#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod aead;
pub mod error;
pub mod hybrid;
pub mod kem;
pub mod sig;
pub mod traits;

pub use error::PrimitivesError;
pub use traits::{HybridKem, Kem, Signature};
