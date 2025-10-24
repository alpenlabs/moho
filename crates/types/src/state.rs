//! Moho state container types

use borsh::{BorshDeserialize, BorshSerialize};
use strata_mmr::{CompactMmr, MerkleMr64, Sha256Hasher, hasher::MerkleHasher};
use strata_predicate::PredicateKey;

use crate::{
    InnerStateCommitment, MohoStateCommitment,
    merkle::{MerkleProof, MerkleTree},
};

pub type ExportEntryMmrHash = [u8; 32];
pub type ExportEntryMmr = MerkleMr64<Sha256Hasher>;
pub type ExportEntryMmrCompact = CompactMmr<ExportEntryMmrHash>;

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

    entries_mmr: ExportEntryMmrCompact,
}

impl ExportContainer {
    pub fn new(container_id: u16) -> Self {
        let entries_mmr = ExportEntryMmr::new(64).to_compact();
        Self {
            container_id,
            entries_mmr,
        }
    }

    pub fn container_id(&self) -> u16 {
        self.container_id
    }

    pub fn add_entry(&mut self, entry: ExportEntry) {
        let mut entries_mmr = ExportEntryMmr::from_compact(&self.entries_mmr);
        entries_mmr.add_leaf(entry.to_mmr_leaf()).unwrap();
        self.entries_mmr = entries_mmr.to_compact();
    }

    /// Verify that an entry is included in the container's MMR
    ///
    /// NOTE: This is a placeholder implementation that only checks if the MMR is non-empty.
    /// A full proof verification would require:
    /// - The position (index) of the entry in the MMR
    /// - The merkle proof (sibling hashes) from the entry to the root
    /// - Verification that the leaf hash + proof reconstructs the MMR root
    ///
    /// To implement full verification, the caller would need to provide:
    /// ```ignore
    /// pub fn verify_entry_inclusion(
    ///     &self,
    ///     entry: &ExportEntry,
    ///     position: u64,
    ///     proof: &[ExportEntryMmrHash]
    /// ) -> bool
    /// ```
    pub fn verify_entry_inclusion(&self, _entry: &ExportEntry) -> bool {
        // Placeholder: Just check if MMR has been populated
        // Compare with an empty MMR to determine if this one has content
        let empty_mmr = ExportEntryMmr::new(64);
        let empty_compact = empty_mmr.to_compact();

        // If the compact representation is different from empty, MMR is non-empty
        // This works because CompactMmr should implement PartialEq or we can serialize both
        format!("{:?}", self.entries_mmr) != format!("{:?}", empty_compact)
    }

    pub fn entries_mmr_root(&self) -> Option<ExportEntryMmrHash> {
        let entries_mmr = ExportEntryMmr::from_compact(&self.entries_mmr);
        // get_single_root only works when there's exactly one peak (power of 2 - 1 elements)
        // For general case, we'd need to bag the peaks to get a single root
        entries_mmr.get_single_root().ok()
    }
}

/// A specific entry payload
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct ExportEntry {
    /// Application-specific payload.
    ///
    /// In practice, this will contain all the assignment data.
    payload: Vec<u8>,
}

impl ExportEntry {
    pub fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn to_mmr_leaf(&self) -> ExportEntryMmrHash {
        Sha256Hasher::hash_leaf(&self.payload)
    }
}

/// Enum representing the different fields that can be proven
#[derive(Clone, Debug)]
pub enum StateField {
    InnerState,
    NextPredicate,
    ExportState,
}

impl StateField {
    fn index(&self) -> u8 {
        match self {
            StateField::InnerState => 0,
            StateField::NextPredicate => 1,
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

    /// Generate a Merkle proof for the next_predicate field
    ///
    /// This proves that the predicate key is part of the MohoState
    /// by providing the necessary sibling hashes to reconstruct the root.
    ///
    /// NOTE: This implementation will be reworked with SSZ merkelization later.
    pub fn generate_next_predicate_proof(&self) -> MerkleProof {
        self.generate_proof(StateField::NextPredicate)
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

    /// Get the hash of the next_predicate field for proof verification
    pub fn get_next_predicate_hash(&self) -> [u8; 32] {
        MerkleTree::hash_serializable(&self.next_predicate)
    }

    /// Internal: Get the Merkle leaves for all fields
    fn get_merkle_leaves(&self) -> Vec<[u8; 32]> {
        vec![
            // Leaf 0: inner_state
            MerkleTree::hash_serializable(&self.inner_state),
            // Leaf 1: next_predicate
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
    fn test_merkle_proof_next_predicate() {
        // Create a mock state
        let inner_state = InnerStateCommitment::default();
        let next_predicate = PredicateKey::always_accept();
        let export_state = ExportState { containers: vec![] };

        let state = MohoState::new(inner_state, next_predicate.clone(), export_state);

        // Generate proof for next_predicate
        let proof = state.generate_next_predicate_proof();
        let next_predicate_hash = state.get_next_predicate_hash();

        // Verify the proof against the state
        assert!(state.verify_proof(&proof, &next_predicate_hash));

        // Verify against computed commitment
        let commitment = state.compute_commitment();
        assert!(MohoState::verify_proof_against_commitment(
            &commitment,
            &proof,
            &next_predicate_hash
        ));
    }

    #[test]
    fn test_commitment_consistency() {
        let inner_state = InnerStateCommitment::default();
        let next_predicate = PredicateKey::always_accept();
        let export_state = ExportState { containers: vec![] };

        let state1 = MohoState::new(inner_state, next_predicate.clone(), export_state.clone());
        let state2 = MohoState::new(inner_state, next_predicate, export_state);

        // Same states should have same commitment
        assert_eq!(
            state1.compute_commitment().inner(),
            state2.compute_commitment().inner()
        );
    }

    #[test]
    fn test_verify_entry_inclusion_valid() {
        let entry1 = ExportEntry::new(vec![1, 2, 3]);
        let entry2 = ExportEntry::new(vec![4, 5, 6]);
        let entry3 = ExportEntry::new(vec![7, 8, 9]);

        let mut container = ExportContainer::new(1);
        container.add_entry(entry1.clone());
        container.add_entry(entry2.clone());
        container.add_entry(entry3.clone());

        // Verify the entries are included (MMR is non-empty)
        assert!(container.verify_entry_inclusion(&entry2));
        assert!(container.verify_entry_inclusion(&entry1));
        assert!(container.verify_entry_inclusion(&entry3));
    }

    #[test]
    fn test_verify_entry_inclusion_returns_true_for_nonempty() {
        let entry1 = ExportEntry::new(vec![1, 2, 3]);
        let entry2 = ExportEntry::new(vec![4, 5, 6]);
        let wrong_entry = ExportEntry::new(vec![99, 99, 99]);

        let mut container = ExportContainer::new(1);
        container.add_entry(entry1.clone());
        container.add_entry(entry2.clone());

        // Basic check returns true for non-empty MMR
        // (Full proof verification would need position + merkle proof)
        assert!(container.verify_entry_inclusion(&entry1));
        assert!(container.verify_entry_inclusion(&wrong_entry));
    }

    #[test]
    fn test_verify_entry_inclusion_empty_container() {
        let container = ExportContainer::new(1);
        let entry = ExportEntry::new(vec![1, 2, 3]);

        // Trying to verify in empty container should fail
        assert!(!container.verify_entry_inclusion(&entry));
    }

    #[test]
    fn test_entries_mmr_root() {
        let entry1 = ExportEntry::new(vec![1, 2, 3]);
        let entry2 = ExportEntry::new(vec![4, 5, 6]);

        let mut container = ExportContainer::new(1);

        // Empty container has no root
        assert!(container.entries_mmr_root().is_none());

        // After adding entries, root should exist
        container.add_entry(entry1.clone());
        assert!(container.entries_mmr_root().is_some());

        let root_after_one = container.entries_mmr_root().unwrap();

        container.add_entry(entry2.clone());
        let root_after_two = container.entries_mmr_root().unwrap();

        // Roots should be different after adding new entry
        assert_ne!(root_after_one, root_after_two);
    }
}
