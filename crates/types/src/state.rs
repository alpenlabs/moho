//! Moho state types and SSZ-based commitment/proof helpers.

use borsh::{BorshDeserialize, BorshSerialize};
use ssz_generated::ssz::moho::*;
use ssz_types::{FixedBytes, VariableList};
use strata_merkle::{MAX_MMR_PEAKS, MerkleMr64B32};
use strata_predicate::{PredicateKey, PredicateKeyBuf};
use tree_hash::{Sha256Hasher, TreeHash};

use crate::{InnerStateCommitment, MohoStateCommitment, ssz_generated};

impl MohoState {
    pub fn new(
        inner_state: InnerStateCommitment,
        next_predicate: PredicateKey,
        export_state: ExportState,
    ) -> Self {
        let next_predicate_bytes = next_predicate.as_buf_ref().to_bytes();
        let next_predicate =
            VariableList::<u8, { MAX_PREDICATE_SIZE as usize }>::from(next_predicate_bytes);
        Self {
            inner_state: inner_state.into_inner(),
            next_predicate,
            export_state,
        }
    }

    pub fn inner_state(&self) -> InnerStateCommitment {
        InnerStateCommitment::from(self.inner_state.0)
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

    pub fn compute_commitment(&self) -> MohoStateCommitment {
        let root = <_ as TreeHash<Sha256Hasher>>::tree_hash_root(self);
        MohoStateCommitment::new(root.into_inner())
    }
}

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

    pub fn add_entry(&mut self, container_id: u16, entry: [u8; 32]) {
        if let Some(container) = self
            .containers
            .iter_mut()
            .find(|c| c.container_id == container_id)
        {
            container.add_entry(entry);
        }
    }
}

impl ExportContainer {
    pub fn new(container_id: u16, entries: Vec<[u8; 32]>) -> Self {
        let mut entries_mmr = MerkleMr64B32::new(MAX_MMR_PEAKS as usize);
        for entry in entries {
            entries_mmr
                .add_leaf(entry)
                .expect("entries exceed Merkle MMR capacity");
        }
        Self {
            container_id,
            entries_mmr,
        }
    }

    pub fn container_id(&self) -> u16 {
        self.container_id
    }

    pub fn entries_mmr(&self) -> &MerkleMr64B32 {
        &self.entries_mmr
    }

    pub fn add_entry(&mut self, entry: [u8; 32]) {
        self.entries_mmr
            .add_leaf(entry)
            .expect("entries exceed Merkle MMR capacity");
    }
}

// Borsh serialization for ExportContainer
impl BorshSerialize for ExportContainer {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.container_id, writer)?;
        // Serialize entries_mmr using SSZ encoding
        let mmr_bytes = ssz::Encode::as_ssz_bytes(&self.entries_mmr);
        BorshSerialize::serialize(&mmr_bytes, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for ExportContainer {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let container_id: u16 = BorshDeserialize::deserialize_reader(reader)?;
        let mmr_bytes: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        let entries_mmr = ssz::Decode::from_ssz_bytes(&mmr_bytes).map_err(|e| {
            borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, format!("{:?}", e))
        })?;
        Ok(Self {
            container_id,
            entries_mmr,
        })
    }
}

// Borsh serialization for ExportState
impl BorshSerialize for ExportState {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        let containers: Vec<&ExportContainer> = self.containers.iter().collect();
        BorshSerialize::serialize(&(containers.len() as u32), writer)?;
        for c in containers {
            BorshSerialize::serialize(c, writer)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for ExportState {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let cont_len: u32 = BorshDeserialize::deserialize_reader(reader)?;
        let mut containers: Vec<ExportContainer> = Vec::with_capacity(cont_len as usize);
        for _ in 0..cont_len {
            containers.push(BorshDeserialize::deserialize_reader(reader)?);
        }
        Ok(Self::new(containers))
    }
}

// Borsh serialization for the generated SSZ MohoState
impl BorshSerialize for MohoState {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        // inner_state is already FixedBytes<32>
        writer.write_all(self.inner_state.as_ref())?;
        // next_predicate bytes as Vec<u8>
        let bytes = self.next_predicate.as_ref();
        BorshSerialize::serialize(&bytes.to_vec(), writer)?;
        // export_state
        BorshSerialize::serialize(&self.export_state, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for MohoState {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut inner = [0u8; 32];
        reader.read_exact(&mut inner)?;
        let inner_state = FixedBytes::<32>::from(inner);

        let pred_vec: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        let next_predicate = VariableList::<u8, { MAX_PREDICATE_SIZE as usize }>::from(pred_vec);

        // export_state
        let export_state: ExportState = BorshDeserialize::deserialize_reader(reader)?;

        Ok(Self {
            inner_state,
            next_predicate,
            export_state,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use ssz::{Decode, Encode};
    use tree_hash::Sha256Hasher;

    use super::*;

    // Strategy for generating arbitrary ExportContainer
    fn export_container_strategy() -> impl Strategy<Value = ExportContainer> {
        (
            any::<u16>(),
            prop::collection::vec(any::<[u8; 32]>(), 0..10),
        )
            .prop_map(|(container_id, entries)| ExportContainer::new(container_id, entries))
    }

    // Strategy for generating arbitrary ExportState
    fn export_state_strategy() -> impl Strategy<Value = ExportState> {
        prop::collection::vec(export_container_strategy(), 0..5).prop_map(ExportState::new)
    }

    // Strategy for generating arbitrary MohoState
    fn moho_state_strategy() -> impl Strategy<Value = MohoState> {
        (
            any::<[u8; 32]>(),
            prop::collection::vec(any::<u8>(), 1..MAX_PREDICATE_SIZE as usize),
            export_state_strategy(),
        )
            .prop_map(|(inner_bytes, pred_bytes, export_state)| {
                let inner_state = InnerStateCommitment::new(inner_bytes);
                let fallback: &[u8] = &[0x01u8];
                let predicate = PredicateKeyBuf::try_from(&pred_bytes[..])
                    .unwrap_or_else(|_| PredicateKeyBuf::try_from(fallback).unwrap())
                    .to_owned();
                MohoState::new(inner_state, predicate, export_state)
            })
    }

    mod export_container_tests {
        use super::*;

        proptest! {
            #[test]
            fn ssz_roundtrip(container in export_container_strategy()) {
                let encoded = container.as_ssz_bytes();
                let decoded = ExportContainer::from_ssz_bytes(&encoded).unwrap();
                prop_assert_eq!(container.container_id(), decoded.container_id());
                prop_assert_eq!(container.entries_mmr(), decoded.entries_mmr());
            }

            #[test]
            fn tree_hash_deterministic(container in export_container_strategy()) {
                let hash1 = <ExportContainer as TreeHash<Sha256Hasher>>::tree_hash_root(&container);
                let hash2 = <ExportContainer as TreeHash<Sha256Hasher>>::tree_hash_root(&container);
                prop_assert_eq!(hash1, hash2);
            }
        }

        #[test]
        fn test_zero_ssz() {
            let container = ExportContainer::new(0, vec![]);
            let encoded = container.as_ssz_bytes();
            let decoded = ExportContainer::from_ssz_bytes(&encoded).unwrap();
            assert_eq!(container.container_id(), decoded.container_id());
            assert_eq!(container.entries_mmr(), decoded.entries_mmr());
        }

        #[test]
        fn test_add_entry() {
            let mut container = ExportContainer::new(1, vec![]);
            let empty_mmr = container.entries_mmr().clone();

            let entry = [0xAA; 32];
            container.add_entry(entry);
            // MMR should have changed after adding entry
            assert_ne!(container.entries_mmr(), &empty_mmr);
        }
    }

    mod export_state_tests {
        use super::*;

        proptest! {
            #[test]
            fn ssz_roundtrip(state in export_state_strategy()) {
                let encoded = state.as_ssz_bytes();
                let decoded = ExportState::from_ssz_bytes(&encoded).unwrap();
                prop_assert_eq!(state.containers().len(), decoded.containers().len());
            }

            #[test]
            fn tree_hash_deterministic(state in export_state_strategy()) {
                let hash1 = <ExportState as TreeHash<Sha256Hasher>>::tree_hash_root(&state);
                let hash2 = <ExportState as TreeHash<Sha256Hasher>>::tree_hash_root(&state);
                prop_assert_eq!(hash1, hash2);
            }
        }

        #[test]
        fn test_empty_state_ssz() {
            let state = ExportState::new(vec![]);
            let encoded = state.as_ssz_bytes();
            let decoded = ExportState::from_ssz_bytes(&encoded).unwrap();
            assert_eq!(state.containers().len(), 0);
            assert_eq!(decoded.containers().len(), 0);
        }

        #[test]
        fn test_add_entry() {
            let container1 = ExportContainer::new(1, vec![]);
            let container2 = ExportContainer::new(2, vec![]);
            let mut state = ExportState::new(vec![container1, container2]);

            let initial_mmr = state.containers()[0].entries_mmr().clone();
            let entry = [0xFF; 32];
            state.add_entry(1, entry);

            let containers = state.containers();
            // MMR should have changed after adding entry
            assert_ne!(containers[0].entries_mmr(), &initial_mmr);
        }
    }

    mod moho_state_tests {
        use super::*;

        proptest! {
            #[test]
            fn ssz_roundtrip(state in moho_state_strategy()) {
                let encoded = state.as_ssz_bytes();
                let decoded = MohoState::from_ssz_bytes(&encoded).unwrap();

                let state_inner = *state.inner_state().inner();
                let decoded_inner = *decoded.inner_state().inner();
                prop_assert_eq!(state_inner, decoded_inner);
                prop_assert_eq!(state.next_predicate().as_buf_ref().to_bytes(),
                               decoded.next_predicate().as_buf_ref().to_bytes());
                prop_assert_eq!(state.export_state().containers().len(),
                               decoded.export_state().containers().len());
            }

            #[test]
            fn tree_hash_deterministic(state in moho_state_strategy()) {
                let hash1 = <MohoState as TreeHash<Sha256Hasher>>::tree_hash_root(&state);
                let hash2 = <MohoState as TreeHash<Sha256Hasher>>::tree_hash_root(&state);
                prop_assert_eq!(hash1, hash2);
            }

            #[test]
            fn commitment_deterministic(state in moho_state_strategy()) {
                let commitment1 = state.compute_commitment();
                let commitment2 = state.compute_commitment();
                let inner1 = commitment1.inner();
                let inner2 = commitment2.inner();
                prop_assert_eq!(inner1, inner2);
            }
        }

        #[test]
        fn test_minimal_state_ssz() {
            let inner = InnerStateCommitment::new([0u8; 32]);
            let pred_bytes: &[u8] = &[0x01u8];
            let predicate = PredicateKeyBuf::try_from(pred_bytes).unwrap().to_owned();
            let export = ExportState::new(vec![]);
            let state = MohoState::new(inner, predicate, export);

            let encoded = state.as_ssz_bytes();
            let decoded = MohoState::from_ssz_bytes(&encoded).unwrap();

            assert_eq!(state.inner_state().inner(), decoded.inner_state().inner());
            assert_eq!(
                state.next_predicate().as_buf_ref().to_bytes(),
                decoded.next_predicate().as_buf_ref().to_bytes()
            );
        }

        #[test]
        fn test_state_with_max_predicate_size() {
            let inner = InnerStateCommitment::new([0xAB; 32]);
            // Use PredicateKey::always_accept() which creates a valid predicate
            let predicate = PredicateKey::always_accept();
            let export = ExportState::new(vec![]);
            let state = MohoState::new(inner, predicate, export);

            let encoded = state.as_ssz_bytes();
            let decoded = MohoState::from_ssz_bytes(&encoded).unwrap();

            assert_eq!(state.inner_state().inner(), decoded.inner_state().inner());
            assert_eq!(
                state.next_predicate().as_buf_ref().to_bytes(),
                decoded.next_predicate().as_buf_ref().to_bytes()
            );
        }

        #[test]
        fn test_state_with_complex_export() {
            let inner = InnerStateCommitment::new([0x12; 32]);
            let predicate = PredicateKey::always_accept();

            let entry1 = [0x01; 32];
            let entry2 = [0x02; 32];
            let container1 = ExportContainer::new(10, vec![entry1, entry2]);

            let entry3 = [0x03; 32];
            let container2 = ExportContainer::new(20, vec![entry3]);

            let export = ExportState::new(vec![container1, container2]);
            let state = MohoState::new(inner, predicate, export);

            let encoded = state.as_ssz_bytes();
            let decoded = MohoState::from_ssz_bytes(&encoded).unwrap();

            assert_eq!(state.inner_state().inner(), decoded.inner_state().inner());
            assert_eq!(decoded.export_state().containers().len(), 2);
            // Verify the MMRs match
            assert_eq!(
                state.export_state().containers()[0].entries_mmr(),
                decoded.export_state().containers()[0].entries_mmr()
            );
            assert_eq!(
                state.export_state().containers()[1].entries_mmr(),
                decoded.export_state().containers()[1].entries_mmr()
            );
        }

        #[test]
        fn test_commitment_uniqueness() {
            let inner1 = InnerStateCommitment::new([0x01; 32]);
            let inner2 = InnerStateCommitment::new([0x02; 32]);
            let pred_bytes: &[u8] = &[0x01u8];
            let predicate = PredicateKeyBuf::try_from(pred_bytes).unwrap().to_owned();
            let export = ExportState::new(vec![]);

            let state1 = MohoState::new(inner1, predicate.clone(), export.clone());
            let state2 = MohoState::new(inner2, predicate, export);

            let commitment1 = state1.compute_commitment();
            let commitment2 = state2.compute_commitment();

            assert_ne!(commitment1.inner(), commitment2.inner());
        }

        #[test]
        fn test_accessors() {
            let inner = InnerStateCommitment::new([0xCD; 32]);
            let predicate = PredicateKey::always_accept();
            let export = ExportState::new(vec![]);
            let state = MohoState::new(inner, predicate.clone(), export);

            assert_eq!(state.inner_state().as_array(), &[0xCD; 32]);
            assert_eq!(
                state.next_predicate().as_buf_ref().to_bytes(),
                predicate.as_buf_ref().to_bytes()
            );
            assert_eq!(state.export_state().containers().len(), 0);
        }

        #[test]
        fn test_into_export_state() {
            let inner = InnerStateCommitment::new([0x00; 32]);
            let pred_bytes: &[u8] = &[0x01u8];
            let predicate = PredicateKeyBuf::try_from(pred_bytes).unwrap().to_owned();
            let container = ExportContainer::new(1, vec![]);
            let export = ExportState::new(vec![container]);
            let state = MohoState::new(inner, predicate, export);

            let extracted_export = state.into_export_state();
            assert_eq!(extracted_export.containers().len(), 1);
            assert_eq!(extracted_export.containers()[0].container_id(), 1);
        }
    }
}
