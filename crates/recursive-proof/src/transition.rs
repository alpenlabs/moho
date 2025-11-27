use moho_types::StateRefAttestation;
use ssz::{Decode, Encode, ssz_encode};
use ssz_derive::{Decode, Encode};
use strata_predicate::PredicateKey;

use crate::errors::{InvalidProofError, TransitionChainError};

/// Represents a state transition between two states of the same type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Encode, Decode)]
pub struct Transition<T: Encode + Decode> {
    /// The state before the transition occurs
    from_state: T,
    /// The state after the transition completes
    to_state: T,
}

impl<T: Encode + Decode> Transition<T> {
    /// Creates a new transition from one state to another.
    ///
    /// # Arguments
    ///
    /// * `from` - The starting state i.e. the state before the transition occurs
    /// * `to` - The destination state i.e. the state after the transition completes
    pub fn new(from: T, to: T) -> Self {
        Self {
            from_state: from,
            to_state: to,
        }
    }

    /// Returns a reference to the starting state before the transition occurs.
    pub fn from(&self) -> &T {
        &self.from_state
    }

    /// Returns a reference to the final state after the transition completes.
    pub fn to(&self) -> &T {
        &self.to_state
    }

    /// Consumes the transition and returns the states before and after the transition.
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
#[derive(Clone, Debug, Encode, Decode)]
pub struct MohoTransitionWithProof {
    transition: MohoStateTransition,
    proof: Vec<u8>,
}

impl MohoTransitionWithProof {
    /// Creates a new `MohoTransitionWithProof` from a state transition and its proof.
    pub fn new(transition: MohoStateTransition, proof: Vec<u8>) -> Self {
        Self { transition, proof }
    }

    /// Returns a reference to the inner `MohoStateTransition`.
    pub fn transition(&self) -> &MohoStateTransition {
        &self.transition
    }

    /// Returns a reference to the associated cryptographic `Proof`.
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Consumes `self` and returns a tuple of the inner `MohoStateTransition` and `Proof`.
    ///
    /// # Returns
    ///
    /// A tuple where the first element is the transition and the second is the proof.
    pub fn into_parts(self) -> (MohoStateTransition, Vec<u8>) {
        (self.transition, self.proof)
    }

    /// Verifies the transition's proof against the given predicate key.
    pub fn verify(&self, verifier: &PredicateKey) -> Result<(), InvalidProofError> {
        let public_values = ssz_encode(&self);
        match verifier.verify_claim_witness(&public_values, self.proof()) {
            Ok(_) => Ok(()),
            // TODO: Better error?
            Err(_) => Err(InvalidProofError(Box::new(self.transition.clone()))),
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::transition::Transition;

//     #[test]
//     fn test_valid_transition_chain() {
//         let first = Transition::new("a", "b");
//         let second = Transition::new("b", "c");

//         let res = first.chain(second).unwrap();
//         assert_eq!(*res.from(), "a");
//         assert_eq!(*res.to(), "c");
//     }

//     #[test]
//     fn test_invalid_transition_chain() {
//         let first = Transition::new("a", "b");
//         let second = Transition::new("b", "c");

//         let res = second.chain(first);
//         assert!(res.is_err());
//     }
// }
