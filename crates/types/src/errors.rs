//! Error types for Moho state operations.

use ssz_types::Error as SszError;
use strata_merkle::MerkleError;
use thiserror::Error;

/// Errors that can occur when working with export state.
#[derive(Debug, Error, PartialEq)]
pub enum ExportStateError {
    /// Failed to add entry to container.
    #[error("Failed to add entry to container: {0}")]
    AddEntryFailed(#[from] MerkleError),

    /// failed
    // TODO: this message is wrong for `ExportState::new`, which also returns this variant when
    // there are more than `MAX_EXPORT_CONTAINERS` containers.
    #[error("Failed to add entry to container: {0}")]
    SszError(#[from] SszError),

    /// Two containers share the same ID.
    #[error("Duplicate export container ID: {0}")]
    DuplicateContainerId(u8),
}
