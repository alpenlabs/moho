//! Moho state types and SSZ-based commitment/proof helpers.

use borsh::{BorshDeserialize, BorshSerialize};
use strata_predicate::PredicateKey;

use crate::{
    InnerStateCommitment, MohoStateCommitment,
    merkle::{MerkleProof, MerkleTree},
    ssz_generated,
};
use ssz_types::VariableList;
use tree_hash::{Sha256Hasher, TreeHash};

// Re-export SSZ-generated types as the canonical Rust types
pub type MohoState = ssz_generated::specs::moho::MohoState;
pub type ExportState = ssz_generated::specs::moho::ExportState;
pub type ExportContainer = ssz_generated::specs::moho::ExportContainer;
pub type ExportEntry = ssz_generated::specs::moho::ExportEntry;

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
    pub fn new(
        inner_state: InnerStateCommitment,
        next_predicate: PredicateKey,
        export_state: ExportState,
    ) -> Self {
        let inner = ssz_types::FixedVector::<u8, 32>::from(inner_state.inner());
        let next_predicate_bytes = borsh::to_vec(&next_predicate)
            .expect("borsh serialization of predicate key");
        let next_predicate = VariableList::<u8, 256>::from(next_predicate_bytes);
        Self { inner_state: inner, next_predicate, export_state }
    }

    pub fn inner_state(&self) -> InnerStateCommitment {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.inner_state[..]);
        InnerStateCommitment::new(arr)
    }

    pub fn next_predicate(&self) -> PredicateKey {
        // Interpret stored bytes as borsh-encoded PredicateKey
        borsh::from_slice(self.next_predicate.as_ref())
            .expect("stored predicate bytes must be valid borsh")
    }

    pub fn export_state(&self) -> &ExportState {
        &self.export_state
    }

    pub fn into_export_state(self) -> ExportState {
        self.export_state
    }

    /// Compute the MohoStateCommitment (Merkle root) of the MohoState
    pub fn compute_commitment(&self) -> MohoStateCommitment {
        let root = <_ as TreeHash<Sha256Hasher>>::tree_hash_root(self);
        MohoStateCommitment::new(root.into_inner())
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
        let leaves = self.get_ssz_field_roots();
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
        <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&self.next_predicate).into_inner()
    }

    /// Internal: Get the Merkle leaves for all fields (SSZ field roots)
    fn get_ssz_field_roots(&self) -> Vec<[u8; 32]> {
        let inner_root = <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&self.inner_state).into_inner();
        let pred_root = <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&self.next_predicate).into_inner();
        let export_root = <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&self.export_state).into_inner();

        vec![inner_root, pred_root, export_root]
    }

    /// Compute the SSZ field root for a predicate key.
    pub fn compute_next_predicate_ssz_root(key: &PredicateKey) -> [u8; 32] {
        let bytes = borsh::to_vec(key).expect("borsh serialization of predicate key");
        // Use VariableList<u8,256> to compute root with mix-in length
        let list: VariableList<u8, 256> = VariableList::from(bytes);
        <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&list).into_inner()
    }
}

// Compatibility constructors and accessors for SSZ-generated types
impl ExportState {
    pub fn new(containers: Vec<ExportContainer>) -> Self {
        Self { containers: ssz_types::VariableList::from(containers) }
    }

    pub fn containers(&self) -> &[ExportContainer] {
        &self.containers
    }

    pub fn add_entry(&mut self, container_id: u16, entry: ExportEntry) {
        if let Some(container) = self
            .containers
            .iter_mut()
            .find(|c| c.container_id == container_id)
        {
            container.entries.push(entry);
        }
    }
}

impl ExportContainer {
    pub fn new(container_id: u16, common_payload: Vec<u8>, entries: Vec<ExportEntry>) -> Self {
        Self {
            container_id,
            common_payload: ssz_types::VariableList::from(common_payload),
            entries: ssz_types::VariableList::from(entries),
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

impl ExportEntry {
    pub fn new(entry_id: u32, payload: Vec<u8>) -> Self {
        Self { entry_id, payload: ssz_types::VariableList::from(payload) }
    }

    pub fn entry_id(&self) -> u32 { self.entry_id }
    pub fn payload(&self) -> &[u8] { &self.payload }
}

// Borsh serialization for the generated SSZ MohoState
impl BorshSerialize for MohoState {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        // inner_state [u8;32]
        writer.write_all(&self.inner_state[..])?;
        // next_predicate bytes as Vec<u8>
        let bytes = self.next_predicate.as_ref();
        BorshSerialize::serialize(&bytes.to_vec(), writer)?;
        // export_state
        // containers: Vec<ExportContainer>
        let containers: Vec<&ExportContainer> = self.export_state.containers.iter().collect();
        BorshSerialize::serialize(&(containers.len() as u32), writer)?;
        for c in containers {
            BorshSerialize::serialize(&c.container_id, writer)?;
            let cp: Vec<u8> = c.common_payload.as_ref().to_vec();
            BorshSerialize::serialize(&cp, writer)?;
            let entries: Vec<&ExportEntry> = c.entries.iter().collect();
            BorshSerialize::serialize(&(entries.len() as u32), writer)?;
            for e in entries {
                BorshSerialize::serialize(&e.entry_id, writer)?;
                let pl: Vec<u8> = e.payload.as_ref().to_vec();
                BorshSerialize::serialize(&pl, writer)?;
            }
        }
        Ok(())
    }
}

impl BorshDeserialize for MohoState {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut inner = [0u8; 32];
        reader.read_exact(&mut inner)?;
        let inner_state = ssz_types::FixedVector::<u8, 32>::from(inner);

        let pred_vec: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        let next_predicate = VariableList::<u8, 256>::from(pred_vec);

        // containers
        let cont_len: u32 = BorshDeserialize::deserialize_reader(reader)?;
        let mut containers: Vec<ExportContainer> = Vec::with_capacity(cont_len as usize);
        for _ in 0..cont_len {
            let container_id: u16 = BorshDeserialize::deserialize_reader(reader)?;
            let common_payload_vec: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
            let common_payload = ssz_types::VariableList::from(common_payload_vec);

            let entries_len: u32 = BorshDeserialize::deserialize_reader(reader)?;
            let mut entries: Vec<ExportEntry> = Vec::with_capacity(entries_len as usize);
            for _ in 0..entries_len {
                let entry_id: u32 = BorshDeserialize::deserialize_reader(reader)?;
                let payload_vec: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
                let payload = ssz_types::VariableList::from(payload_vec);
                entries.push(ExportEntry { entry_id, payload });
            }

            containers.push(ExportContainer { container_id, common_payload, entries: ssz_types::VariableList::from(entries) });
        }

        let export_state = ExportState { containers: ssz_types::VariableList::from(containers) };

        Ok(Self { inner_state, next_predicate, export_state })
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
        let export_state = ExportState::new(vec![]);

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
        let export_state1 = ExportState::new(vec![]);
        let export_state2 = ExportState::new(vec![]);

        let state1 = MohoState::new(inner_state, next_predicate.clone(), export_state1);
        let state2 = MohoState::new(inner_state, next_predicate, export_state2);

        // Same states should have same commitment
        assert_eq!(
            state1.compute_commitment().inner(),
            state2.compute_commitment().inner()
        );
    }
}
