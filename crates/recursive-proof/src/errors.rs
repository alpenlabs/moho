use std::fmt::Debug;

use moho_types::StateRefAttestation;
use thiserror::Error;

use crate::transition::MohoStateTransition;

/// Errors that can occur when working with Moho state transitions.
#[derive(Error, Debug)]
pub enum MohoError {
    /// Indicates that two transitions cannot be chained because the end of the first
    /// does not align with the start of the second.
    #[error(transparent)]
    InvalidMohoChain(#[from] TransitionChainError<StateRefAttestation>),

    /// Occurs when the incremental proof for a transition is invalid.
    #[error("invalid incremental proof for transition {0:?}")]
    InvalidIncrementalProof(#[source] InvalidProofError),

    /// Occurs when the recursive proof for a transition is invalid.
    #[error("invalid recursive proof for transition {0:?}")]
    InvalidRecursiveProof(#[source] InvalidProofError),

    /// Indicates that a Merkle proof provided is invalid.
    #[error("invalid merkle proof")]
    InvalidMerkleProof,
}

#[derive(Debug, Error)]
#[error(
    "Cannot chain transitions: first transition ends at {first_end_state:?}, but second starts at {second_start_state:?}"
)]
pub struct TransitionChainError<T>
where
    T: Debug,
{
    /// The end state of the first transition
    pub first_end_state: T,
    /// The start state of the second transition  
    pub second_start_state: T,
}

#[derive(Debug, Error)]
#[error("Cannot prove validity of the moho state transition {0:?}")]
pub struct InvalidProofError(MohoStateTransition);
