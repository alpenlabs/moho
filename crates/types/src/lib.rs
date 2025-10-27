//! moho types

mod constants;
mod id;
mod ssz_merkle_utils;
mod relation;
mod state;

pub use constants::*;
pub use id::{InnerStateCommitment, MohoStateCommitment, StateReference};
pub use ssz_merkle_utils::{SszLeafInclusionProof, SszFieldMerkle, SszFieldRoots};
pub use relation::{MohoAttestation, StateRefAttestation};
pub use state::{ExportContainer, ExportEntry, ExportState, MohoState};

// Generated SSZ types live here at compile time
pub mod ssz_generated {
    // Makes tree_hash and ssz traits available to generated code
    pub use ssz::{Decode as SszDecode, Encode as SszEncode};
    pub use ssz_types::*;
    pub use tree_hash::TreeHash;

    include!(concat!(env!("OUT_DIR"), "/generated_ssz.rs"));
}
