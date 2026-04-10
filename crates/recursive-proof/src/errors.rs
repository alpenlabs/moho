use moho_types::{RecursiveMohoAttestation, StateRefAttestation, StepMohoAttestation};
use strata_predicate::PredicateError;
use thiserror::Error;

/// Errors that can occur when working with Moho state transitions.
///
/// Several variants contain large payloads (attestations, proof errors). Rather than
/// suppressing `clippy::result_large_err` with `#[allow]`, we box the large fields so that
/// `Result<_, MohoError>` stays small on the stack. This matters because the error path is
/// cold while the success path — which pays for the `Result` size — is hot.
#[derive(Error, Debug)]
pub enum MohoError {
    /// The recursive proof's proven state does not match the step proof's starting state.
    #[error(
        "cannot chain attestations: recursive proof ends at {recursive_end}, but step proof starts at {step_start}"
    )]
    InvalidMohoChain {
        /// The proven state of the recursive attestation.
        recursive_end: Box<StateRefAttestation>,
        /// The starting state of the step attestation.
        step_start: Box<StateRefAttestation>,
    },

    /// The incremental step proof is invalid.
    #[error("invalid incremental proof: {0}")]
    InvalidIncrementalProof(#[source] Box<InvalidStepProofError>),

    /// The recursive proof is invalid.
    #[error("invalid recursive proof: {0}")]
    InvalidRecursiveProof(#[source] Box<InvalidRecursiveProofError>),

    /// A Merkle inclusion proof is invalid.
    #[error("invalid merkle proof")]
    InvalidMerkleProof,
}

#[derive(Debug, Error)]
#[error("{attestation}: {source}")]
pub struct InvalidStepProofError {
    pub attestation: StepMohoAttestation,
    #[source]
    pub source: PredicateError,
}

#[derive(Debug, Error)]
#[error("{attestation}: {source}")]
pub struct InvalidRecursiveProofError {
    pub attestation: RecursiveMohoAttestation,
    #[source]
    pub source: PredicateError,
}
