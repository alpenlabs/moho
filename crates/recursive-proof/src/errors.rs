use std::fmt::Debug;

use moho_types::StateRefAttestation;
use thiserror::Error;

use crate::transition::{MohoStateTransition, Transition};

#[derive(Error, Debug)]
pub enum MohoError {
    #[error(transparent)]
    InvalidMohoChain(#[from] TransitionChainError<StateRefAttestation>),

    #[error("invalid incremental proof for transition {0:?}")]
    InvalidIncrementalProof(MohoStateTransition),

    #[error("invalid recursive proof for transition {0:?}")]
    InvalidRecursiveProof(MohoStateTransition),

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
