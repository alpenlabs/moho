//! Moho state container types

use borsh::{BorshDeserialize, BorshSerialize};
use strata_predicate::PredicateKey;

use crate::{
    InnerStateCommitment, MohoStateCommitment,
    merkle::{MerkleProof, MerkleTree},
};

/// The Moho outer state.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MohoState {
    /// The inner state's commitment.
    ///
    /// The Moho layer can't introspect this itself.  It's passed as an input to
    /// the proof.
    inner_state: InnerStateCommitment,

    /// The predicate key used for the validation of next state transition.
    next_predicate: PredicateKey,

    /// Export state to be read by consumers.
    ///
    /// In practice, this will be the bridge proofs.
    export_state: ExportState,
}

impl MohoState {
    pub fn new(
        inner_state: InnerStateCommitment,
        next_predicate: PredicateKey,
        export_state: ExportState,
    ) -> Self {
        Self {
            inner_state,
            next_predicate,
            export_state,
        }
    }

    pub fn inner_state(&self) -> InnerStateCommitment {
        self.inner_state
    }

    pub fn next_predicate(&self) -> &PredicateKey {
        &self.next_predicate
    }

    pub fn export_state(&self) -> &ExportState {
        &self.export_state
    }

    pub fn into_export_state(self) -> ExportState {
        self.export_state
    }
}

/// Exported state for consumers.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct ExportState {
    /// List of export containers.
    ///
    /// This MUST be sorted by the `container_id` and MUST NOT contain
    /// entries with duplicate `container_id`s.
    containers: Vec<ExportContainer>,
}

impl ExportState {
    pub fn new(containers: Vec<ExportContainer>) -> Self {
        Self { containers }
    }

    pub fn containers(&self) -> &[ExportContainer] {
        &self.containers
    }

    pub fn add_entry(&mut self, container_id: u16, entry: ExportEntry) {
        // REVIEW: check if ignoring if container_id is a good enough solution
        if let Some(container) = self
            .containers
            .iter_mut()
            .find(|container| container.container_id() == container_id)
        {
            container.add_entry(entry);
        }
    }
}

/// Container intended to be consumed by a particular protocol.
///
/// In practice, this will be bridges.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct ExportContainer {
    /// Export container ID.
    ///
    /// In practice, this will be the bridge ID.
    container_id: u16,

    /// Common shared payload data.
    common_payload: Vec<u8>,

    /// List of entries in the export.
    ///
    /// This MUST be sorted by `entry_id` and MUST NOT contain entries with
    /// duplicate `entry_id`s.
    entries: Vec<ExportEntry>,
}

impl ExportContainer {
    pub fn new(container_id: u16, common_payload: Vec<u8>, entries: Vec<ExportEntry>) -> Self {
        Self {
            container_id,
            common_payload,
            entries,
        }
    }

    pub fn container_id(&self) -> u16 {
        self.container_id
    }

    pub fn common_payload(&self) -> &[u8] {
        &self.common_payload
    }

    pub fn entries(&self) -> &[ExportEntry] {
        &self.entries
    }

    pub fn add_entry(&mut self, entry: ExportEntry) {
        self.entries.push(entry);
    }
}

/// A specific entry payload
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct ExportEntry {
    /// Export entry ID.
    ///
    /// In practice, this will be correspond to withdrawal IDs.
    entry_id: u32,

    /// Application-specific payload.
    ///
    /// In practice, this will contain all the assignment data.
    payload: Vec<u8>,
}

impl ExportEntry {
    pub fn new(entry_id: u32, payload: Vec<u8>) -> Self {
        Self { entry_id, payload }
    }

    pub fn entry_id(&self) -> u32 {
        self.entry_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Enum representing the different fields that can be proven
#[derive(Clone, Debug)]
pub enum StateField {
    InnerState,
    NextVk,
    ExportState,
}

impl StateField {
    fn index(&self) -> u8 {
        match self {
            StateField::InnerState => 0,
            StateField::NextVk => 1,
            StateField::ExportState => 2,
        }
    }
}

impl MohoState {
    /// Compute the MohoStateCommitment (Merkle root) of the MohoState
    ///
    /// This creates a simple binary Merkle tree with the three main fields:
    /// - inner_state (leaf 0)
    /// - next_vk (leaf 1)
    /// - export_state (leaf 2)
    ///
    /// The tree is padded to the next power of 2 for simplicity.
    ///
    /// NOTE: This is a temporary implementation using Borsh serialization and SHA256.
    /// Will be replaced with SSZ serialization and merkelization in the future.
    pub fn compute_commitment(&self) -> MohoStateCommitment {
        let leaves = self.get_merkle_leaves();
        let root = MerkleTree::compute_root(&leaves);
        MohoStateCommitment::new(root)
    }

    /// Generate a Merkle proof for the next_vk field
    ///
    /// This proves that the InnerVerificationKey is part of the MohoState
    /// by providing the necessary sibling hashes to reconstruct the root.
    ///
    /// NOTE: This implementation will be reworked with SSZ merkelization later.
    pub fn generate_next_vk_proof(&self) -> MerkleProof {
        self.generate_proof(StateField::NextVk)
    }

    /// Generate a Merkle proof for any field in the state
    pub fn generate_proof(&self, field: StateField) -> MerkleProof {
        let leaves = self.get_merkle_leaves();
        let leaf_index = field.index() as usize;
        MerkleTree::generate_proof(&leaves, leaf_index)
    }

    /// Verify a Merkle proof against a given MohoStateCommitment
    pub fn verify_proof_against_commitment(
        commitment: &MohoStateCommitment,
        proof: &MerkleProof,
        leaf_value: &[u8; 32],
    ) -> bool {
        MerkleTree::verify_proof(commitment.inner(), proof, leaf_value)
    }

    /// Verify a Merkle proof against this state's commitment
    pub fn verify_proof(&self, proof: &MerkleProof, leaf_value: &[u8; 32]) -> bool {
        let commitment = self.compute_commitment();
        Self::verify_proof_against_commitment(&commitment, proof, leaf_value)
    }

    /// Get the hash of the next_vk field for proof verification
    pub fn get_next_vk_hash(&self) -> [u8; 32] {
        MerkleTree::hash_serializable(&self.next_predicate)
    }

    /// Internal: Get the Merkle leaves for all fields
    fn get_merkle_leaves(&self) -> Vec<[u8; 32]> {
        vec![
            // Leaf 0: inner_state
            MerkleTree::hash_serializable(&self.inner_state),
            // Leaf 1: next_vk
            MerkleTree::hash_serializable(&self.next_predicate),
            // Leaf 2: export_state
            MerkleTree::hash_serializable(&self.export_state),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_proof_next_vk() {
        // Create a mock state
        let inner_state = InnerStateCommitment::default();
        let next_vk = PredicateKey::always_accept();
        let export_state = ExportState { containers: vec![] };

        let state = MohoState::new(inner_state, next_vk.clone(), export_state);

        // Generate proof for next_vk
        let proof = state.generate_next_vk_proof();
        let next_vk_hash = state.get_next_vk_hash();

        // Verify the proof against the state
        assert!(state.verify_proof(&proof, &next_vk_hash));

        // Verify against computed commitment
        let commitment = state.compute_commitment();
        assert!(MohoState::verify_proof_against_commitment(
            &commitment,
            &proof,
            &next_vk_hash
        ));
    }

    #[test]
    fn test_commitment_consistency() {
        let inner_state = InnerStateCommitment::default();
        let next_vk = PredicateKey::always_accept();
        let export_state = ExportState { containers: vec![] };

        let state1 = MohoState::new(inner_state, next_vk.clone(), export_state.clone());
        let state2 = MohoState::new(inner_state, next_vk, export_state);

        // Same states should have same commitment
        assert_eq!(
            state1.compute_commitment().inner(),
            state2.compute_commitment().inner()
        );
    }
}
