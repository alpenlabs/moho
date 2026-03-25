use ssz_derive::{Decode, Encode};
use strata_merkle::MerkleProofB32;
use strata_predicate::PredicateKey;

use crate::{MohoStateTransition, transition::MohoTransitionWithProof};
/// Input data for generating a recursive Moho proof that combines incremental and recursive proofs.
///
/// `MohoRecursiveInput` contains all the necessary components to create a new recursive proof
/// by combining a previous recursive proof (if it exists) with a new incremental step proof.
/// This enables efficient proof composition where each new recursive proof can represent
/// an arbitrarily long chain of state transitions while maintaining constant verification time.
#[derive(Debug, Clone, Encode, Decode)]
pub struct MohoRecursiveInput {
    /// Moho proof's own predicate key, necessary to verify the previous recursive proof
    pub(crate) moho_predicate: PredicateKey,
    /// Previous recursive moho proof
    pub(crate) prev_recursive_proof: Option<MohoTransitionWithProof>,
    /// Incremental step proof
    pub(crate) incremental_step_proof: MohoTransitionWithProof,
    /// Predicate key to verify the incremental step proof from initial_state to final_state
    pub(crate) step_predicate: PredicateKey,
    /// Merkle proof of `step_predicate` within initial_state
    pub(crate) step_predicate_merkle_proof: MerkleProofB32,
}

impl MohoRecursiveInput {
    /// Creates a new [`MohoRecursiveInput`].
    pub fn new(
        moho_predicate: PredicateKey,
        prev_recursive_proof: Option<MohoTransitionWithProof>,
        incremental_step_proof: MohoTransitionWithProof,
        step_predicate: PredicateKey,
        step_predicate_merkle_proof: MerkleProofB32,
    ) -> Self {
        Self {
            moho_predicate,
            prev_recursive_proof,
            incremental_step_proof,
            step_predicate,
            step_predicate_merkle_proof,
        }
    }

    /// Returns the moho predicate key used to verify the previous recursive proof.
    pub fn moho_predicate(&self) -> &PredicateKey {
        &self.moho_predicate
    }

    /// Returns the previous recursive moho proof, if any.
    pub fn prev_recursive_proof(&self) -> Option<&MohoTransitionWithProof> {
        self.prev_recursive_proof.as_ref()
    }

    /// Returns the incremental step proof.
    pub fn incremental_step_proof(&self) -> &MohoTransitionWithProof {
        &self.incremental_step_proof
    }

    /// Returns the predicate key used to verify the incremental step proof.
    pub fn step_predicate(&self) -> &PredicateKey {
        &self.step_predicate
    }

    /// Returns the merkle proof of the step predicate within the initial state.
    pub fn step_predicate_merkle_proof(&self) -> &MerkleProofB32 {
        &self.step_predicate_merkle_proof
    }
}

/// Output data committed by a recursive Moho proof that verifiers must check.
///
/// `MohoRecursiveOutput` contains the committed information produced by a recursive proof.
/// The verifier of this proof needs to ensure that the correct recursive predicate was used,
/// so we commit the `moho_predicate` as public output. Since we cannot hardcode this outer
/// predicate key in the circuit, it must be included as a public parameter for verification.
#[derive(Debug, Clone, Encode, Decode)]
pub struct MohoRecursiveOutput {
    /// State transition proven by this recursive proof
    pub(crate) transition: MohoStateTransition,
    /// Predicate key used to verify previous recursive proof, committed as public output
    /// to ensure verifiers can confirm the correct predicate was used
    pub(crate) moho_predicate: PredicateKey,
}

impl MohoRecursiveOutput {
    /// Creates a new [`MohoRecursiveOutput`].
    pub fn new(transition: MohoStateTransition, moho_predicate: PredicateKey) -> Self {
        Self {
            transition,
            moho_predicate,
        }
    }

    /// Returns the state transition proven by this recursive proof.
    pub fn transition(&self) -> &MohoStateTransition {
        &self.transition
    }

    /// Returns the predicate key committed as public output.
    pub fn moho_predicate(&self) -> &PredicateKey {
        &self.moho_predicate
    }
}
