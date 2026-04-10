//! Runtime implementation for computing Moho state transitions.
//!
//! This crate provides [`compute_moho_attestation`], which executes a single incremental
//! state transition defined by a [`MohoProgram`](moho_runtime_interface::MohoProgram)
//! and produces a [`StepMohoAttestation`](moho_types::StepMohoAttestation) — the public
//! parameter consumed by the recursive proof.
//!
//! Downstream consumers implement the [`MohoProgram`](moho_runtime_interface::MohoProgram)
//! trait (defining their inner state types and transition logic), then call
//! [`compute_moho_attestation`] inside their proof program.

mod input;
mod runtime;

pub use input::RuntimeInput;
pub use runtime::compute_moho_attestation;
