use std::fmt::Debug;

use moho_types::StateRefAttestation;
use thiserror::Error;

/// Errors that can occur when working with Moho state transitions.
#[derive(Error, Debug)]
pub enum MohoError {
    /// Two attestations cannot be chained because the end of the first
    /// does not align with the start of the second.
    #[error(transparent)]
    InvalidMohoChain(#[from] Box<TransitionChainError<StateRefAttestation>>),

    /// The incremental step proof is invalid.
    #[error("invalid incremental proof: {0}")]
    InvalidIncrementalProof(#[source] InvalidProofError),

    /// The recursive proof is invalid.
    #[error("invalid recursive proof: {0}")]
    InvalidRecursiveProof(#[source] InvalidProofError),

    /// A Merkle inclusion proof is invalid.
    #[error("invalid merkle proof")]
    InvalidMerkleProof,
}

#[derive(Debug, Error)]
#[error(
    "Cannot chain attestations: first ends at {first_end_state:?}, but second starts at {second_start_state:?}"
)]
pub struct TransitionChainError<T>
where
    T: Debug,
{
    /// The end state of the first attestation.
    pub first_end_state: T,
    /// The start state of the second attestation.
    pub second_start_state: T,
}

#[derive(Debug, Error)]
#[error("Cannot prove validity of attestation: {0}")]
pub struct InvalidProofError(pub String);
