//! Moho state types and SSZ-based commitment/proof helpers.

use borsh::{BorshDeserialize, BorshSerialize};
use ssz_generated::ssz::moho::*;
use ssz_types::VariableList;
use strata_predicate::{PredicateKey, PredicateKeyBuf};
use tree_hash::{Sha256Hasher, TreeHash};

use crate::{
    InnerStateCommitment, MohoStateCommitment, ssz_generated, ssz_merkle_utils::SszFieldRoots,
};

impl MohoState {
    pub fn new(
        inner_state: InnerStateCommitment,
        next_predicate: PredicateKey,
        export_state: ExportState,
    ) -> Self {
        let inner = ssz_types::FixedVector::<u8, 32>::from(*inner_state.inner());
        let next_predicate_bytes = next_predicate.as_buf_ref().to_bytes();
        let next_predicate =
            VariableList::<u8, { MAX_PREDICATE_SIZE as usize }>::from(next_predicate_bytes);
        Self {
            inner_state: inner,
            next_predicate,
            export_state,
        }
    }

    pub fn inner_state(&self) -> InnerStateCommitment {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.inner_state[..]);
        InnerStateCommitment::new(arr)
    }

    pub fn next_predicate(&self) -> PredicateKey {
        PredicateKeyBuf::try_from(&self.next_predicate[..])
            .unwrap()
            .to_owned()
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
}

impl SszFieldRoots for MohoState {
    fn ssz_field_roots(&self) -> Vec<[u8; 32]> {
        let inner_root =
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&self.inner_state).into_inner();
        let pred_root =
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&self.next_predicate).into_inner();
        let export_root =
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&self.export_state).into_inner();

        vec![inner_root, pred_root, export_root]
    }
}

// Additional container types could implement a similar method via SSZ codegen.

// Compatibility constructors and accessors for SSZ-generated types
impl ExportState {
    pub fn new(containers: Vec<ExportContainer>) -> Self {
        Self {
            containers: ssz_types::VariableList::from(containers),
        }
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
            container.entries.push(entry).expect("entry out of bound")
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
        self.entries.push(entry).expect("entry out of bound");
    }
}

impl ExportEntry {
    pub fn new(entry_id: u32, payload: Vec<u8>) -> Self {
        Self {
            entry_id,
            payload: ssz_types::VariableList::from(payload),
        }
    }

    pub fn entry_id(&self) -> u32 {
        self.entry_id
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
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
        let next_predicate =
            VariableList::<u8, { MAX_PREDICATE_SIZE as usize }>::from(pred_vec);

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

            containers.push(ExportContainer {
                container_id,
                common_payload,
                entries: ssz_types::VariableList::from(entries),
            });
        }

        let export_state = ExportState {
            containers: ssz_types::VariableList::from(containers),
        };

        Ok(Self {
            inner_state,
            next_predicate,
            export_state,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssz_merkle_utils::SszFieldMerkle;

    #[test]
    fn test_merkle_proof_next_predicate() {
        // Create a mock state
        let inner_state = InnerStateCommitment::default();
        let next_predicate = PredicateKey::always_accept();
        let export_state = ExportState::new(vec![]);

        let state = MohoState::new(inner_state, next_predicate.clone(), export_state);

        // Generate proof for next_predicate (field index 1)
        let proof = SszFieldMerkle::generate_proof_for_container(&state, 1);
        let next_predicate_hash = state.ssz_field_roots()[1];

        // Verify the proof against the state
        let commitment = state.compute_commitment();
        assert!(SszFieldMerkle::verify_proof(
            commitment.inner(),
            &proof,
            &next_predicate_hash
        ));

        // Verify against computed commitment
        let commitment = state.compute_commitment();
        assert!(SszFieldMerkle::verify_proof(
            commitment.inner(),
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
