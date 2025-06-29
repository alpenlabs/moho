//! Moho recursive proof processing.
//!
//! This crate ties together the key components required to construct, verify,
//! and commit recursive Moho proofs in a zkVM environment.

mod errors;
mod program;
mod statements;
mod transition;

pub use errors::MohoError;
pub use program::{MohoRecursiveInput, MohoRecursiveProgram};
pub use statements::{process_recursive_moho_proof, verify_and_chain_transition};
pub use transition::{MohoStateTransition, MohoTransitionWithProof};
