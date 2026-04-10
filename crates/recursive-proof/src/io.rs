use moho_types::{RecursiveMohoAttestation, RecursiveMohoProof, StepMohoProof};
use ssz_derive::{Decode, Encode};
use strata_merkle::MerkleProofB32;
use strata_predicate::PredicateKey;

/// Input data for generating a recursive Moho proof.
///
/// Contains all the components needed to create a new recursive proof by combining a previous
/// recursive proof (if any) with a new step proof. The recursive proof is extended by verifying
/// both proofs and checking that they are continuous.
#[derive(Debug, Clone, Encode, Decode)]
pub struct MohoRecursiveInput {
    /// Predicate key for verifying the previous recursive proof.
    pub(crate) moho_predicate: PredicateKey,
    /// Previous recursive proof, if this is not the first step.
    pub(crate) prev_recursive_proof: Option<RecursiveMohoProof>,
    /// Predicate key for verifying the incremental step proof.
    pub(crate) step_predicate: PredicateKey,
    /// The new step proof to chain onto the recursive attestation.
    pub(crate) incremental_step_proof: StepMohoProof,
    /// Merkle proof that `step_predicate` is included in the starting state.
    pub(crate) step_predicate_merkle_proof: MerkleProofB32,
}

impl MohoRecursiveInput {
    /// Creates a new [`MohoRecursiveInput`].
    pub fn new(
        moho_predicate: PredicateKey,
        prev_recursive_proof: Option<RecursiveMohoProof>,
        incremental_step_proof: StepMohoProof,
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
    pub fn prev_recursive_proof(&self) -> Option<&RecursiveMohoProof> {
        self.prev_recursive_proof.as_ref()
    }

    /// Returns the incremental step proof.
    pub fn incremental_step_proof(&self) -> &StepMohoProof {
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

/// Public output committed by a recursive Moho proof.
///
/// Contains the attestation (genesis-to-proven chain) and the predicate key used to verify
/// the recursive proof itself. The predicate is included because it cannot be hardcoded in the
/// circuit — verifiers need it to confirm the correct predicate was used.
#[derive(Debug, Clone, Encode, Decode)]
pub struct MohoRecursiveOutput {
    /// The recursive attestation proven by this proof.
    pub(crate) attestation: RecursiveMohoAttestation,
    /// Predicate key committed as public output so verifiers can confirm the correct
    /// predicate was used.
    pub(crate) moho_predicate: PredicateKey,
}

impl MohoRecursiveOutput {
    /// Creates a new [`MohoRecursiveOutput`].
    pub fn new(attestation: RecursiveMohoAttestation, moho_predicate: PredicateKey) -> Self {
        Self {
            attestation,
            moho_predicate,
        }
    }

    /// Returns the recursive attestation proven by this proof.
    pub fn attestation(&self) -> &RecursiveMohoAttestation {
        &self.attestation
    }

    /// Returns the predicate key committed as public output.
    pub fn moho_predicate(&self) -> &PredicateKey {
        &self.moho_predicate
    }
}
