//! Moho attestation types for proving state transitions.
//!
//! Moho uses two kinds of attestations:
//!
//! - A [`StepMohoAttestation`] proves a single state transition from one state to the next.
//! - A [`RecursiveMohoAttestation`] proves an aggregated chain of transitions from a genesis state
//!   to some proven state.
//!
//! To extend a recursive attestation, we verify both the existing recursive proof and a new step
//! proof, then check that they are continuous — i.e., the proven state of the recursive
//! attestation matches the starting state of the step attestation. If so, the recursive
//! attestation advances to the step's target state while preserving the original genesis.

use std::fmt;

use ssz_derive::{Decode, Encode};
use thiserror::Error;

use crate::{MohoStateCommitment, StateReference};

/// Error returned by [`RecursiveMohoAttestation::chain`] when the recursive attestation's proven
/// state does not match the step attestation's starting state.
#[derive(Debug, Clone, Error)]
#[error(
    "cannot chain attestations: recursive proof ends at {recursive_end}, but step proof starts at {step_start}"
)]
pub struct ChainError {
    /// The proven state of the recursive attestation.
    pub recursive_end: StateRefAttestation,
    /// The starting state of the step attestation.
    pub step_start: StateRefAttestation,
}

/// An aggregated attestation proving a chain of state transitions from genesis to some proven
/// state.
///
/// Created by recursively chaining [`StepMohoAttestation`]s: each call to [`chain`](Self::chain)
/// verifies continuity between the current proven state and the step's starting state, then
/// advances the proven state to the step's target.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecursiveMohoAttestation {
    /// The fixed starting point of the attestation chain.
    genesis: StateRefAttestation,

    /// The most recent state proven as reachable from genesis through a sequence of valid steps.
    proven: StateRefAttestation,
}

impl RecursiveMohoAttestation {
    pub fn new(genesis: StateRefAttestation, proven: StateRefAttestation) -> Self {
        Self { genesis, proven }
    }

    pub fn genesis(&self) -> &StateRefAttestation {
        &self.genesis
    }

    pub fn proven(&self) -> &StateRefAttestation {
        &self.proven
    }

    /// Extends this recursive attestation with a step attestation, producing a new recursive
    /// attestation that covers the combined range.
    ///
    /// Succeeds only if the attestations are continuous — i.e., the current proven state matches
    /// the step's starting state. The resulting attestation retains the same genesis but advances
    /// the proven state to the step's target.
    ///
    /// Returns a [`ChainError`] carrying the mismatched endpoints if there is a gap between the
    /// two attestations.
    #[allow(
        clippy::result_large_err,
        reason = "Ok variant is already the same size as ChainError, so boxing Err wouldn't shrink the Result"
    )]
    pub fn chain(
        self: RecursiveMohoAttestation,
        step: StepMohoAttestation,
    ) -> Result<Self, ChainError> {
        if self.proven() == step.from() {
            Ok(RecursiveMohoAttestation::new(self.genesis, step.to))
        } else {
            Err(ChainError {
                recursive_end: self.proven,
                step_start: step.from,
            })
        }
    }
}

impl fmt::Display for RecursiveMohoAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} => {}", self.genesis, self.proven)
    }
}

/// An attestation proving a single state transition step.
///
/// This is the building block for [`RecursiveMohoAttestation`]. Each step attests that the
/// state machine validly transitioned from one state to the next.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StepMohoAttestation {
    /// The state before the transition.
    from: StateRefAttestation,

    /// The state after the transition.
    to: StateRefAttestation,
}

impl StepMohoAttestation {
    pub fn new(from: StateRefAttestation, to: StateRefAttestation) -> Self {
        Self { from, to }
    }

    pub fn from(&self) -> &StateRefAttestation {
        &self.from
    }

    pub fn to(&self) -> &StateRefAttestation {
        &self.to
    }

    pub fn into_parts(self) -> (StateRefAttestation, StateRefAttestation) {
        (self.from, self.to)
    }
}

impl fmt::Display for StepMohoAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.from, self.to)
    }
}

/// A [`StepMohoAttestation`] bundled with the cryptographic proof that backs it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StepMohoProof {
    /// The claim being proven.
    attestation: StepMohoAttestation,

    /// The raw proof bytes that attest to the step transition's validity.
    proof: Vec<u8>,
}

impl StepMohoProof {
    pub fn new(attestation: StepMohoAttestation, proof: Vec<u8>) -> Self {
        Self { attestation, proof }
    }

    pub fn attestation(&self) -> &StepMohoAttestation {
        &self.attestation
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    pub fn into_attestation(self) -> StepMohoAttestation {
        self.attestation
    }
}

/// A [`RecursiveMohoAttestation`] bundled with the cryptographic proof that backs it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecursiveMohoProof {
    /// The claim being proven.
    attestation: RecursiveMohoAttestation,

    /// The raw proof bytes that attest to the recursive transition's validitiy.
    proof: Vec<u8>,
}

impl RecursiveMohoProof {
    pub fn new(attestation: RecursiveMohoAttestation, proof: Vec<u8>) -> Self {
        Self { attestation, proof }
    }

    pub fn attestation(&self) -> &RecursiveMohoAttestation {
        &self.attestation
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    pub fn into_parts(self) -> (RecursiveMohoAttestation, Vec<u8>) {
        (self.attestation, self.proof)
    }
}

/// A binding between a [`StateReference`] and the [`MohoStateCommitment`] it resolves to.
///
/// This pairing is what both step and recursive attestations operate on — equality of two
/// `StateRefAttestation` values is what establishes continuity between attestations.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateRefAttestation {
    /// An opaque identifier for the state (e.g. a block hash).
    reference: StateReference,

    /// The commitment to the full [`MohoState`](crate::MohoState) at this reference.
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

impl fmt::Display for StateRefAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.reference, self.commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a [`StateRefAttestation`] with both fields derived from a single byte.
    fn state_ref(byte: u8) -> StateRefAttestation {
        StateRefAttestation::new(
            StateReference::new([byte; 32]),
            MohoStateCommitment::new([byte; 32]),
        )
    }

    #[test]
    fn state_ref_attestation_equality() {
        let a = state_ref(1);
        let b = state_ref(1);
        let c = state_ref(2);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn chain_continuous_step_succeeds() {
        let s0 = state_ref(0);
        let s1 = state_ref(1);
        let s2 = state_ref(2);

        let rec = RecursiveMohoAttestation::new(s0, s1);
        let step = StepMohoAttestation::new(s1, s2);

        let chained = rec.chain(step).expect("continuous chain should succeed");
        assert_eq!(*chained.genesis(), s0, "genesis must be preserved");
        assert_eq!(*chained.proven(), s2, "proven must advance to step target");
    }

    #[test]
    fn chain_discontinuous_step_returns_err() {
        let s0 = state_ref(0);
        let s1 = state_ref(1);
        let bad_from = state_ref(3);
        let bad_to = state_ref(4);

        let rec = RecursiveMohoAttestation::new(s0, s1);
        let step = StepMohoAttestation::new(bad_from, bad_to);

        let err = rec.chain(step).expect_err("gap should cause chain to fail");
        assert_eq!(err.recursive_end, s1);
        assert_eq!(err.step_start, bad_from);
    }

    #[test]
    fn chain_multiple_steps() {
        let s0 = state_ref(0);
        let s1 = state_ref(1);
        let s2 = state_ref(2);
        let s3 = state_ref(3);

        let rec = RecursiveMohoAttestation::new(s0, s1);

        let rec = rec
            .chain(StepMohoAttestation::new(s1, s2))
            .expect("step 1→2 should chain");
        let rec = rec
            .chain(StepMohoAttestation::new(s2, s3))
            .expect("step 2→3 should chain");

        assert_eq!(*rec.genesis(), s0, "genesis stays fixed across all chains");
        assert_eq!(*rec.proven(), s3, "proven reaches final step target");
    }

    #[test]
    fn chain_fails_midway_on_gap() {
        let s0 = state_ref(0);
        let s1 = state_ref(1);
        let s2 = state_ref(2);

        let rec = RecursiveMohoAttestation::new(s0, s1);
        let rec = rec
            .chain(StepMohoAttestation::new(s1, s2))
            .expect("first chain should succeed");

        let bad_step = StepMohoAttestation::new(state_ref(10), state_ref(11));
        assert!(rec.chain(bad_step).is_err(), "gap mid-chain should fail");
    }
}
