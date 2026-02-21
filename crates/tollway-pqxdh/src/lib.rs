//! Post-Quantum Extended Diffie-Hellman (PQXDH).
//!
//! Scope Boundary: This crate handles key schedule derivation only.
//! It does not implement the Double Ratchet. It does not define messaging formats.
//! It does not touch storage, networking, or identity logic.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod bundle;
pub mod error;
pub mod session;

pub use bundle::PrekeyBundle;
pub use session::{PqxdhInitiator, PqxdhResponder};
