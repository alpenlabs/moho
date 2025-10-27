//! moho types

mod id;
mod relation;
mod ssz_merkle_utils;
mod state;

pub use id::{InnerStateCommitment, MohoStateCommitment, StateReference};
pub use relation::{MohoAttestation, StateRefAttestation};
pub use ssz_merkle_utils::{SszFieldMerkle, SszFieldRoots, SszLeafInclusionProof};
pub use state::{ExportContainer, ExportEntry, ExportState, MohoState};

// Generated SSZ types live here at compile time
pub mod ssz_generated {
    // Makes tree_hash and ssz traits available to generated code
    pub use ssz::{Decode as SszDecode, Encode as SszEncode};
    pub use ssz_types::*;
    pub use tree_hash::TreeHash;

    include!(concat!(env!("OUT_DIR"), "/generated_ssz.rs"));
}
