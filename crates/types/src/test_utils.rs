//! Proptest strategies shared by the tests in this crate.

use proptest::prelude::*;

use crate::{ExportContainer, ExportState};

type Hash32 = [u8; 32];

/// Generates a container with an arbitrary ID and up to 10 entries.
pub(crate) fn export_container_strategy() -> impl Strategy<Value = ExportContainer> {
    any::<u8>().prop_flat_map(export_container_with_id)
}

/// Generates an export state with up to 5 containers. IDs are unique, as
/// `ExportState::new` requires, and come in arbitrary order.
pub(crate) fn export_state_strategy() -> impl Strategy<Value = ExportState> {
    prop::sample::subsequence((0..=u8::MAX).collect::<Vec<_>>(), 0..5)
        .prop_shuffle()
        .prop_flat_map(|ids| {
            ids.into_iter()
                .map(export_container_with_id)
                .collect::<Vec<_>>()
        })
        .prop_map(|containers| ExportState::new(containers).unwrap())
}

fn export_container_with_id(container_id: u8) -> impl Strategy<Value = ExportContainer> {
    prop::collection::vec(any::<Hash32>(), 0..10).prop_map(move |entries| {
        let mut container = ExportContainer::new(container_id);
        for entry in entries {
            container.add_entry(entry).expect("failed to add entry");
        }
        container
    })
}
