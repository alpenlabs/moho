//! Moho state types and SSZ-based commitment/proof helpers.

use ssz_generated::ssz::moho::*;
use strata_merkle::{CompactMmr64, MAX_MMR_PEAKS, Mmr, Mmr64B32, Sha256Hasher as MerkleHasher};
use tree_hash::{Sha256Hasher, TreeHash};

type Hash32 = [u8; 32];

use crate::{InnerStateCommitment, MohoStateCommitment, errors::ExportStateError, ssz_generated};

impl MohoState {
    /// Creates a new Moho state.
    pub fn new(
        inner_state: InnerStateCommitment,
        next_predicate: PredicateKey,
        export_state: ExportState,
    ) -> Self {
        Self {
            inner_state: inner_state.into_inner().into(),
            next_predicate,
            export_state,
        }
    }

    /// Returns the inner state commitment.
    pub fn inner_state(&self) -> InnerStateCommitment {
        InnerStateCommitment::from(self.inner_state.0)
    }

    /// Returns the predicate key for verifying the next incremental proof.
    pub fn next_predicate(&self) -> &PredicateKey {
        &self.next_predicate
    }

    /// Returns a reference to the export state.
    pub fn export_state(&self) -> &ExportState {
        &self.export_state
    }

    /// Consumes self and returns the export state.
    pub fn into_export_state(self) -> ExportState {
        self.export_state
    }

    /// Computes the commitment to this Moho state via tree hash.
    pub fn compute_commitment(&self) -> MohoStateCommitment {
        MohoStateCommitment::from(<_ as TreeHash<Sha256Hasher>>::tree_hash_root(self))
    }
}

// Compatibility constructors and accessors for SSZ-generated types
impl ExportState {
    /// Creates a new export state with the given containers.
    pub fn new(containers: Vec<ExportContainer>) -> Self {
        Self {
            containers: ssz_types::VariableList::from(containers),
        }
    }

    /// Returns a slice of all containers.
    pub fn containers(&self) -> &[ExportContainer] {
        &self.containers
    }

    /// Adds an entry to the container with the specified ID.
    ///
    /// If a container with the given `container_id` exists, the entry is appended to its MMR.
    /// If no container exists with that ID, a new container is created and the entry is added.
    ///
    /// # Errors
    ///
    /// Returns `ExportStateError::AddEntryFailed` if the MMR capacity is exceeded.
    ///
    /// # Panics
    ///
    /// This method will never panic in practice because `MAX_EXPORT_CONTAINERS = 256` exactly
    /// matches the full range of `u8` container IDs (0-255). Since each container_id is unique,
    /// we can never exceed the container list capacity.
    pub fn add_entry(&mut self, container_id: u8, entry: Hash32) -> Result<(), ExportStateError> {
        if let Some(container) = self
            .containers
            .iter_mut()
            .find(|c| c.container_id == container_id)
        {
            container.add_entry(entry)?;
        } else {
            let mut new_container = ExportContainer::new(container_id);
            new_container.add_entry(entry)?;
            // SAFETY: MAX_EXPORT_CONTAINERS = 256 matches the full range of u8 (0-255),
            // so we can never exceed capacity with unique container_ids
            self.containers
                .push(new_container)
                .expect("container capacity should never be exceeded with u8 container_id");
        }
        Ok(())
    }
}

impl ExportContainer {
    /// Creates a new export container with an empty MMR and default empty/zeroed out extra data.
    pub fn new(container_id: u8) -> Self {
        let mmr = CompactMmr64::<Hash32>::new(MAX_MMR_PEAKS as u8);
        let entries_mmr = Mmr64B32::from_generic(&mmr);
        Self {
            container_id,
            extra_data: Hash32::default().into(),
            entries_mmr,
        }
    }

    /// Returns the container ID.
    pub fn container_id(&self) -> u8 {
        self.container_id
    }

    /// Returns the container extra data.
    pub fn extra_data(&self) -> &Hash32 {
        &self.extra_data.0
    }

    /// Returns a reference to the entries MMR.
    pub fn entries_mmr(&self) -> &Mmr64B32 {
        &self.entries_mmr
    }

    /// Adds an entry to the container's MMR.
    ///
    /// # Errors
    ///
    /// Returns `ExportStateError::AddEntryFailed` if the MMR capacity is exceeded.
    pub fn add_entry(&mut self, entry: Hash32) -> Result<(), ExportStateError> {
        let mut mmr = self.entries_mmr.to_generic();
        Mmr::<MerkleHasher>::add_leaf(&mut mmr, entry)?;
        self.entries_mmr = Mmr64B32::from_generic(&mmr);
        Ok(())
    }

    /// Updates the extra data of the container.
    pub fn update_extra_data(&mut self, extra_data: Hash32) {
        self.extra_data = extra_data.into()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use ssz::{Decode, Encode};
    use tree_hash::Sha256Hasher;

    use super::*;

    /// Helper function to create an always_accept predicate
    fn always_accept() -> PredicateKey {
        PredicateKey {
            id: 1, // AlwaysAccept ID
            condition: vec![].into(),
        }
    }

    fn predicate_strategy() -> impl Strategy<Value = PredicateKey> {
        (any::<u8>(), prop::collection::vec(any::<u8>(), 0..8)).prop_map(|(id, condition)| {
            PredicateKey {
                id,
                condition: condition.into(),
            }
        })
    }

    fn export_container_strategy() -> impl Strategy<Value = ExportContainer> {
        (any::<u8>(), prop::collection::vec(any::<Hash32>(), 0..10)).prop_map(
            |(container_id, entries)| {
                let mut container = ExportContainer::new(container_id);
                for entry in entries {
                    container.add_entry(entry).expect("failed to add entry");
                }
                container
            },
        )
    }

    fn export_state_strategy() -> impl Strategy<Value = ExportState> {
        prop::collection::vec(export_container_strategy(), 0..5).prop_map(ExportState::new)
    }

    fn moho_state_strategy() -> impl Strategy<Value = MohoState> {
        (
            any::<Hash32>(),
            predicate_strategy(),
            export_state_strategy(),
        )
            .prop_map(|(inner_bytes, predicate, export_state)| {
                let inner_state = InnerStateCommitment::from(inner_bytes);
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
                let hash1 = <ExportContainer as tree_hash::TreeHash<Sha256Hasher>>::tree_hash_root(&container);
                let hash2 = <ExportContainer as tree_hash::TreeHash<Sha256Hasher>>::tree_hash_root(&container);
                prop_assert_eq!(hash1, hash2);
            }
        }

        #[test]
        fn test_zero_ssz() {
            let container = ExportContainer::new(0);
            let encoded = container.as_ssz_bytes();
            let decoded = ExportContainer::from_ssz_bytes(&encoded).unwrap();
            assert_eq!(container.container_id(), decoded.container_id());
            assert_eq!(container.entries_mmr(), decoded.entries_mmr());
        }

        #[test]
        fn test_add_entry() {
            let mut container = ExportContainer::new(1);
            let empty_mmr = container.entries_mmr().clone();

            let entry = [0xAA; 32];
            container.add_entry(entry).unwrap();
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
                let hash1 = <ExportState as tree_hash::TreeHash<Sha256Hasher>>::tree_hash_root(&state);
                let hash2 = <ExportState as tree_hash::TreeHash<Sha256Hasher>>::tree_hash_root(&state);
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
            let container1 = ExportContainer::new(1);
            let container2 = ExportContainer::new(2);
            let mut state = ExportState::new(vec![container1, container2]);

            let initial_mmr = state.containers()[0].entries_mmr().clone();
            let entry = [0xFF; 32];
            state.add_entry(1, entry).unwrap();

            let containers = state.containers();
            // MMR should have changed after adding entry
            assert_ne!(containers[0].entries_mmr(), &initial_mmr);
        }

        #[test]
        fn test_add_entry_creates_container() {
            let mut state = ExportState::new(vec![]);
            let entry = [0x11; 32];

            state.add_entry(42, entry).unwrap();

            let containers = state.containers();
            assert_eq!(containers.len(), 1);
            assert_eq!(containers[0].container_id(), 42);
            assert_eq!(containers[0].entries_mmr().num_entries(), 1);
        }
    }

    mod moho_state_tests {
        use super::*;

        proptest! {
            #[test]
            fn ssz_roundtrip(state in moho_state_strategy()) {
                let encoded = state.as_ssz_bytes();
                let decoded = MohoState::from_ssz_bytes(&encoded).unwrap();

                let state_inner = state.inner_state().into_inner();
                let decoded_inner = decoded.inner_state().into_inner();
                prop_assert_eq!(state_inner, decoded_inner);
                prop_assert_eq!(
                    state.next_predicate(),
                    decoded.next_predicate()
                );
                prop_assert_eq!(
                    state.export_state().containers().len(),
                    decoded.export_state().containers().len()
                );
            }

            #[test]
            fn tree_hash_deterministic(state in moho_state_strategy()) {
                let hash1 = <MohoState as tree_hash::TreeHash<Sha256Hasher>>::tree_hash_root(&state);
                let hash2 = <MohoState as tree_hash::TreeHash<Sha256Hasher>>::tree_hash_root(&state);
                prop_assert_eq!(hash1, hash2);
            }

            #[test]
            fn commitment_deterministic(state in moho_state_strategy()) {
                let commitment1 = state.compute_commitment();
                let commitment2 = state.compute_commitment();
                let inner1 = commitment1.into_inner();
                let inner2 = commitment2.into_inner();
                prop_assert_eq!(inner1, inner2);
            }
        }

        #[test]
        fn test_minimal_state_ssz() {
            let inner = InnerStateCommitment::from(Hash32::default());
            let predicate = always_accept();
            let export = ExportState::new(vec![]);
            let state = MohoState::new(inner, predicate, export);

            let encoded = state.as_ssz_bytes();
            let decoded = MohoState::from_ssz_bytes(&encoded).unwrap();

            assert_eq!(
                state.inner_state().into_inner(),
                decoded.inner_state().into_inner()
            );
            assert_eq!(state.next_predicate(), decoded.next_predicate());
        }

        #[test]
        fn test_state_with_valid_predicate() {
            let inner = InnerStateCommitment::from([0xAB; 32]);
            let predicate = always_accept();
            let export = ExportState::new(vec![]);
            let state = MohoState::new(inner, predicate, export);

            let encoded = state.as_ssz_bytes();
            let decoded = MohoState::from_ssz_bytes(&encoded).unwrap();

            assert_eq!(
                state.inner_state().into_inner(),
                decoded.inner_state().into_inner()
            );
            assert_eq!(state.next_predicate(), decoded.next_predicate());
        }

        #[test]
        fn test_state_with_complex_export() {
            let inner = InnerStateCommitment::from([0x12; 32]);
            let predicate = always_accept();

            let entry1 = [0x01; 32];
            let entry2 = [0x02; 32];
            let mut container1 = ExportContainer::new(10);
            container1.add_entry(entry1).unwrap();
            container1.add_entry(entry2).unwrap();

            let entry3 = [0x03; 32];
            let mut container2 = ExportContainer::new(20);
            container2.add_entry(entry3).unwrap();

            let export = ExportState::new(vec![container1, container2]);
            let state = MohoState::new(inner, predicate, export);

            let encoded = state.as_ssz_bytes();
            let decoded = MohoState::from_ssz_bytes(&encoded).unwrap();

            assert_eq!(
                state.inner_state().into_inner(),
                decoded.inner_state().into_inner()
            );
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
            let inner1 = InnerStateCommitment::from([0x01; 32]);
            let inner2 = InnerStateCommitment::from([0x02; 32]);
            let predicate = always_accept();
            let export = ExportState::new(vec![]);

            let state1 = MohoState::new(inner1, predicate.clone(), export.clone());
            let state2 = MohoState::new(inner2, predicate, export);

            let commitment1 = state1.compute_commitment();
            let commitment2 = state2.compute_commitment();

            assert_ne!(commitment1.into_inner(), commitment2.into_inner());
        }

        #[test]
        fn test_accessors() {
            let inner = InnerStateCommitment::from([0xCD; 32]);
            let predicate = always_accept();
            let export = ExportState::new(vec![]);
            let state = MohoState::new(inner, predicate.clone(), export);

            assert_eq!(state.inner_state().inner(), &[0xCD; 32]);
            assert_eq!(state.next_predicate(), &predicate);
            assert_eq!(state.export_state().containers().len(), 0);
        }

        #[test]
        fn test_into_export_state() {
            let inner = InnerStateCommitment::from(Hash32::default());
            let predicate = always_accept();
            let container = ExportContainer::new(1);
            let export = ExportState::new(vec![container]);
            let state = MohoState::new(inner, predicate, export);

            let extracted_export = state.into_export_state();
            assert_eq!(extracted_export.containers().len(), 1);
            assert_eq!(extracted_export.containers()[0].container_id(), 1);
        }
    }
}
