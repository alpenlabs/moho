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

use ssz_derive::{Decode, Encode};

use crate::{MohoStateCommitment, StateReference};

/// An aggregated attestation proving a chain of state transitions from genesis to some proven
/// state.
///
/// Created by recursively chaining [`StepMohoAttestation`]s: each call to [`chain`](Self::chain)
/// verifies continuity between the current proven state and the step's starting state, then
/// advances the proven state to the step's target.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
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
    /// Returns `Some` only if the attestations are continuous — i.e., the current proven state
    /// matches the step's starting state. The resulting attestation retains the same genesis but
    /// advances the proven state to the step's target.
    ///
    /// Returns `None` if there is a gap between the two attestations.
    pub fn chain(self: RecursiveMohoAttestation, step: StepMohoAttestation) -> Option<Self> {
        if self.proven() == step.from() {
            Some(RecursiveMohoAttestation::new(self.genesis, step.to))
        } else {
            None
        }
    }
}

/// An attestation proving a single state transition step.
///
/// This is the building block for [`RecursiveMohoAttestation`]. Each step attests that the
/// state machine validly transitioned from one state to the next.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
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
}

/// A [`StepMohoAttestation`] bundled with the cryptographic proof that backs it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
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
}

/// A [`RecursiveMohoAttestation`] bundled with the cryptographic proof that backs it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
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
}

/// A binding between a [`StateReference`] and the [`MohoStateCommitment`] it resolves to.
///
/// This pairing is what both step and recursive attestations operate on — equality of two
/// `StateRefAttestation` values is what establishes continuity between attestations.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
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

        let rec = RecursiveMohoAttestation::new(s0.clone(), s1.clone());
        let step = StepMohoAttestation::new(s1, s2.clone());

        let chained = rec.chain(step).expect("continuous chain should succeed");
        assert_eq!(*chained.genesis(), s0, "genesis must be preserved");
        assert_eq!(*chained.proven(), s2, "proven must advance to step target");
    }

    #[test]
    fn chain_discontinuous_step_returns_none() {
        let s0 = state_ref(0);
        let s1 = state_ref(1);

        let rec = RecursiveMohoAttestation::new(s0, s1);
        let step = StepMohoAttestation::new(state_ref(3), state_ref(4));

        assert!(rec.chain(step).is_none(), "gap should cause chain to fail");
    }

    #[test]
    fn chain_multiple_steps() {
        let s0 = state_ref(0);
        let s1 = state_ref(1);
        let s2 = state_ref(2);
        let s3 = state_ref(3);

        let rec = RecursiveMohoAttestation::new(s0.clone(), s1.clone());

        let rec = rec
            .chain(StepMohoAttestation::new(s1, s2.clone()))
            .expect("step 1→2 should chain");
        let rec = rec
            .chain(StepMohoAttestation::new(s2, s3.clone()))
            .expect("step 2→3 should chain");

        assert_eq!(*rec.genesis(), s0, "genesis stays fixed across all chains");
        assert_eq!(*rec.proven(), s3, "proven reaches final step target");
    }

    #[test]
    fn chain_fails_midway_on_gap() {
        let s0 = state_ref(0);
        let s1 = state_ref(1);
        let s2 = state_ref(2);

        let rec = RecursiveMohoAttestation::new(s0, s1.clone());
        let rec = rec
            .chain(StepMohoAttestation::new(s1, s2))
            .expect("first chain should succeed");

        let bad_step = StepMohoAttestation::new(state_ref(10), state_ref(11));
        assert!(rec.chain(bad_step).is_none(), "gap mid-chain should fail");
    }
}
