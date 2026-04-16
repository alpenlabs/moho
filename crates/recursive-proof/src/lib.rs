//! Moho recursive proof processing.
//!
//! This crate ties together the key components required to construct, verify,
//! and commit recursive Moho proofs in a zkVM environment.

mod errors;
mod io;
#[cfg(not(target_os = "zkvm"))]
mod program;
mod statements;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use errors::MohoError;
pub use io::{MohoRecursiveInput, MohoRecursiveOutput};
#[cfg(not(target_os = "zkvm"))]
pub use program::MohoRecursiveProgram;
pub use statements::{process_recursive_moho_proof, verify_and_chain};
