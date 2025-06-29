use borsh::{BorshDeserialize, BorshSerialize};
use moho_types::StateRefAttestation;
use zkaleido::{Proof, VerifyingKey};

use crate::errors::{InvalidProofError, TransitionChainError};

/// Represents a state transition between two states of the same type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct Transition<T> {
    /// The state before the transition occurs
    from_state: T,
    /// The state after the transition completes
    to_state: T,
}

impl<T> Transition<T> {
    /// Creates a new transition from one state to another.
    ///
    /// # Arguments
    ///
    /// * `from` - The starting state
    /// * `to` - The destination state
    pub fn new(from: T, to: T) -> Self {
        Self {
            from_state: from,
            to_state: to,
        }
    }

    /// Returns a reference to the source state of this transition.
    pub fn from(&self) -> &T {
        &self.from_state
    }

    /// Returns a reference to the target state of this transition.
    pub fn to(&self) -> &T {
        &self.to_state
    }

    /// Consumes the transition and returns the source and target states as a tuple.
    pub fn into_states(self) -> (T, T) {
        (self.from_state, self.to_state)
    }

    /// Returns `true` if this transition represents no change (from and to states are equal).
    pub fn is_no_op(&self) -> bool
    where
        T: PartialEq,
    {
        self.from_state == self.to_state
    }

    /// Merges this transition with another transition to create a single composite transition.
    ///
    /// The `to` state of this transition must equal the `from` state of the next transition.
    /// The result is a transition from this transition's `from` state to the next transition's `to`
    /// state.
    pub fn chain(self, next: Self) -> Result<Self, TransitionChainError<T>>
    where
        T: PartialEq + std::fmt::Debug,
    {
        if self.to_state == next.from_state {
            Ok(Self {
                from_state: self.from_state,
                to_state: next.to_state,
            })
        } else {
            Err(TransitionChainError {
                first_end_state: self.to_state,
                second_start_state: next.from_state,
            })
        }
    }
}

/// Represents a state transition in the Moho protocol, capturing the movement
/// between two attested state references with their corresponding commitments.
pub type MohoStateTransition = Transition<StateRefAttestation>;

/// A state transition accompanied by cryptographic proof of its validity.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MohoTransitionWithProof {
    transition: MohoStateTransition,
    proof: Proof,
}

impl MohoTransitionWithProof {
    pub fn new(transition: MohoStateTransition, proof: Proof) -> Self {
        Self { transition, proof }
    }

    pub fn transition(&self) -> &MohoStateTransition {
        &self.transition
    }

    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    pub fn verify(&self, vk: VerifyingKey) -> Result<(), InvalidProofError> {
        Ok(())
    }
}
