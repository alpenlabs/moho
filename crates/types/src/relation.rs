//! Public commitments to Moho relations.
//!
//! Conceptually, the Moho proof attests to correctness of the state of some
//! inner state machine and its public exports as of some state reference.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{MohoStateCommitment, StateReference};

/// The aggregated state transformation that we are verifying with a Moho proof.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MohoAttestation {
    /// Commitment to the base case state.
    ///
    /// In practice, this is the Moho wrapping around an ASM state.
    genesis: StateRefAttestation,

    /// The ref to the state we prove as a chain from the genesis state.
    proven: StateRefAttestation,
}

impl MohoAttestation {
    pub fn new(genesis: StateRefAttestation, proven: StateRefAttestation) -> Self {
        Self { genesis, proven }
    }

    pub fn genesis(&self) -> &StateRefAttestation {
        &self.genesis
    }

    pub fn proven(&self) -> &StateRefAttestation {
        &self.proven
    }
}

/// A mapping of a state reference to its corresponding state commitment.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct StateRefAttestation {
    reference: StateReference,
    commitment: MohoStateCommitment,
}

impl StateRefAttestation {
    pub fn new(reference: StateReference, commitment: MohoStateCommitment) -> Self {
        Self {
            reference,
            commitment,
        }
    }

    pub fn reference(&self) -> &StateReference {
        &self.reference
    }

    pub fn commitment(&self) -> &MohoStateCommitment {
        &self.commitment
    }
}
