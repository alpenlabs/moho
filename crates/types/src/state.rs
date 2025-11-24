//! Moho state types and SSZ-based commitment/proof helpers.

use borsh::{BorshDeserialize, BorshSerialize};
use ssz_generated::ssz::moho::*;
use ssz_types::{FixedBytes, VariableList};
use strata_predicate::{PredicateKey, PredicateKeyBuf};
use tree_hash::{Sha256Hasher, TreeHash};

use crate::{InnerStateCommitment, MohoStateCommitment, ssz_generated};

impl MohoState {
    pub fn new(
        inner_state: InnerStateCommitment,
        next_predicate: PredicateKey,
        export_state: ExportState,
    ) -> Self {
        let inner = FixedBytes::<32>::from(*inner_state.inner());
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
        arr.copy_from_slice(self.inner_state.as_ref());
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

// Borsh serialization for ExportEntry
impl BorshSerialize for ExportEntry {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.entry_id, writer)?;
        let payload: Vec<u8> = self.payload.as_ref().to_vec();
        BorshSerialize::serialize(&payload, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for ExportEntry {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let entry_id: u32 = BorshDeserialize::deserialize_reader(reader)?;
        let payload: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        Ok(Self::new(entry_id, payload))
    }
}

// Borsh serialization for ExportContainer
impl BorshSerialize for ExportContainer {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.container_id, writer)?;
        let cp: Vec<u8> = self.common_payload.as_ref().to_vec();
        BorshSerialize::serialize(&cp, writer)?;
        let entries: Vec<&ExportEntry> = self.entries.iter().collect();
        BorshSerialize::serialize(&(entries.len() as u32), writer)?;
        for e in entries {
            BorshSerialize::serialize(e, writer)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for ExportContainer {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let container_id: u16 = BorshDeserialize::deserialize_reader(reader)?;
        let common_payload_vec: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        let entries_len: u32 = BorshDeserialize::deserialize_reader(reader)?;
        let mut entries: Vec<ExportEntry> = Vec::with_capacity(entries_len as usize);
        for _ in 0..entries_len {
            entries.push(BorshDeserialize::deserialize_reader(reader)?);
        }
        Ok(Self::new(container_id, common_payload_vec, entries))
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
        // inner_state [u8;32]
        writer.write_all(self.inner_state.as_ref())?;
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
        let inner_state = FixedBytes::<32>::from(inner);

        let pred_vec: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        let next_predicate = VariableList::<u8, { MAX_PREDICATE_SIZE as usize }>::from(pred_vec);

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
    use proptest::prelude::*;
    use ssz::{Decode, Encode};
    use tree_hash::{Sha256Hasher, TreeHash};

    use super::*;

    // Strategy for generating arbitrary ExportEntry
    fn export_entry_strategy() -> impl Strategy<Value = ExportEntry> {
        (any::<u32>(), prop::collection::vec(any::<u8>(), 0..100))
            .prop_map(|(entry_id, payload)| ExportEntry::new(entry_id, payload))
    }

    // Strategy for generating arbitrary ExportContainer
    fn export_container_strategy() -> impl Strategy<Value = ExportContainer> {
        (
            any::<u16>(),
            prop::collection::vec(any::<u8>(), 0..100),
            prop::collection::vec(export_entry_strategy(), 0..10),
        )
            .prop_map(|(container_id, common_payload, entries)| {
                ExportContainer::new(container_id, common_payload, entries)
            })
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

    mod export_entry_tests {
        use super::*;

        proptest! {
            #[test]
            fn ssz_roundtrip(entry_id in any::<u32>(), payload in prop::collection::vec(any::<u8>(), 0..100)) {
                let entry = ExportEntry::new(entry_id, payload.clone());
                let encoded = entry.as_ssz_bytes();
                let decoded = ExportEntry::from_ssz_bytes(&encoded).unwrap();
                prop_assert_eq!(entry.entry_id(), decoded.entry_id());
                prop_assert_eq!(entry.payload(), decoded.payload());
            }

            #[test]
            fn tree_hash_deterministic(entry in export_entry_strategy()) {
                let hash1 = <ExportEntry as TreeHash<Sha256Hasher>>::tree_hash_root(&entry);
                let hash2 = <ExportEntry as TreeHash<Sha256Hasher>>::tree_hash_root(&entry);
                prop_assert_eq!(hash1, hash2);
            }
        }

        #[test]
        fn test_zero_ssz() {
            let entry = ExportEntry::new(0, vec![]);
            let encoded = entry.as_ssz_bytes();
            let decoded = ExportEntry::from_ssz_bytes(&encoded).unwrap();
            assert_eq!(entry.entry_id(), decoded.entry_id());
            assert_eq!(entry.payload(), decoded.payload());
        }

        #[test]
        fn test_max_payload_size() {
            let max_payload = vec![0xFF; MAX_PAYLOAD_SIZE as usize];
            let entry = ExportEntry::new(u32::MAX, max_payload.clone());
            let encoded = entry.as_ssz_bytes();
            let decoded = ExportEntry::from_ssz_bytes(&encoded).unwrap();
            assert_eq!(entry.entry_id(), decoded.entry_id());
            assert_eq!(entry.payload(), decoded.payload());
        }
    }

    mod export_container_tests {
        use super::*;

        proptest! {
            #[test]
            fn ssz_roundtrip(container in export_container_strategy()) {
                let encoded = container.as_ssz_bytes();
                let decoded = ExportContainer::from_ssz_bytes(&encoded).unwrap();
                prop_assert_eq!(container.container_id(), decoded.container_id());
                prop_assert_eq!(container.common_payload(), decoded.common_payload());
                prop_assert_eq!(container.entries().len(), decoded.entries().len());
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
            let container = ExportContainer::new(0, vec![], vec![]);
            let encoded = container.as_ssz_bytes();
            let decoded = ExportContainer::from_ssz_bytes(&encoded).unwrap();
            assert_eq!(container.container_id(), decoded.container_id());
            assert_eq!(container.common_payload(), decoded.common_payload());
            assert_eq!(container.entries().len(), 0);
        }

        #[test]
        fn test_add_entry() {
            let mut container = ExportContainer::new(1, vec![0x01, 0x02], vec![]);
            assert_eq!(container.entries().len(), 0);

            let entry = ExportEntry::new(100, vec![0xAA, 0xBB]);
            container.add_entry(entry);
            assert_eq!(container.entries().len(), 1);
            assert_eq!(container.entries()[0].entry_id(), 100);
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
            let container1 = ExportContainer::new(1, vec![0x01], vec![]);
            let container2 = ExportContainer::new(2, vec![0x02], vec![]);
            let mut state = ExportState::new(vec![container1, container2]);

            let entry = ExportEntry::new(999, vec![0xFF]);
            state.add_entry(1, entry);

            let containers = state.containers();
            assert_eq!(containers[0].entries().len(), 1);
            assert_eq!(containers[0].entries()[0].entry_id(), 999);
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

            let entry1 = ExportEntry::new(1, vec![0x01, 0x02, 0x03]);
            let entry2 = ExportEntry::new(2, vec![0x04, 0x05]);
            let container1 = ExportContainer::new(10, vec![0xAA], vec![entry1, entry2]);

            let entry3 = ExportEntry::new(3, vec![0x06]);
            let container2 = ExportContainer::new(20, vec![0xBB, 0xCC], vec![entry3]);

            let export = ExportState::new(vec![container1, container2]);
            let state = MohoState::new(inner, predicate, export);

            let encoded = state.as_ssz_bytes();
            let decoded = MohoState::from_ssz_bytes(&encoded).unwrap();

            assert_eq!(state.inner_state().inner(), decoded.inner_state().inner());
            assert_eq!(decoded.export_state().containers().len(), 2);
            assert_eq!(decoded.export_state().containers()[0].entries().len(), 2);
            assert_eq!(decoded.export_state().containers()[1].entries().len(), 1);
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

            assert_eq!(state.inner_state().inner(), &[0xCD; 32]);
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
            let container = ExportContainer::new(1, vec![0xAA], vec![]);
            let export = ExportState::new(vec![container]);
            let state = MohoState::new(inner, predicate, export);

            let extracted_export = state.into_export_state();
            assert_eq!(extracted_export.containers().len(), 1);
            assert_eq!(extracted_export.containers()[0].container_id(), 1);
        }
    }
}
