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

impl MohoState {
    pub fn new(
        inner_state: InnerStateCommitment,
        next_vk: InnerVerificationKey,
        export_state: ExportState,
    ) -> Self {
        Self {
            inner_state,
            next_vk,
            export_state,
        }
    }

    pub fn inner_state(&self) -> InnerStateCommitment {
        self.inner_state
    }

    pub fn next_vk(&self) -> &InnerVerificationKey {
        &self.next_vk
    }

    pub fn export_state(&self) -> &ExportState {
        &self.export_state
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
