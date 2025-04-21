//! Moho state container types

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{InnerStateCommitment, InnerVerificationKey};

/// The Moho outer state.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MohoState {
    /// The inner state's commitment.
    ///
    /// The Moho layer can't introspect this itself.  It's passed as an input to
    /// the proof.
    inner_state: InnerStateCommitment,

    /// The verification key used for the next state transition.
    next_vk: InnerVerificationKey,

    /// Export state to be read by consumers.
    ///
    /// In practice, this will be the bridge proofs.
    export_state: ExportState,
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
