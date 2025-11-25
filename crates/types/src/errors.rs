//! Error types for Moho state operations.

use strata_merkle::error::MerkleError;
use thiserror::Error;

/// Errors that can occur when working with export state.
#[derive(Debug, Error, PartialEq)]
pub enum ExportStateError {
    /// Failed to add entry to container.
    #[error("Failed to add entry to container: {0}")]
    AddEntryFailed(#[from] MerkleError),
}
