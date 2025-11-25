//! Error types for Moho state operations.

use strata_merkle::error::MerkleError;
use thiserror::Error;

/// Errors that can occur when working with export state.
#[derive(Debug, Error, PartialEq)]
pub enum ExportStateError {
    /// Container with the specified ID was not found.
    #[error("Container with id {0} not found")]
    ContainerNotFound(u8),

    /// Failed to add entry to container.
    #[error("Failed to add entry to container: {0}")]
    AddEntryFailed(#[from] MerkleError),
}
