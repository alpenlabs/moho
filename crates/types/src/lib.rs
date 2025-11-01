//! moho types

mod id;
mod relation;
mod state;

pub use id::{InnerStateCommitment, MohoStateCommitment, StateReference};
pub use relation::{MohoAttestation, StateRefAttestation};

// Generated SSZ types live here at compile time (kept private)
mod ssz_generated {
    include!(concat!(env!("OUT_DIR"), "/generated_ssz.rs"));
}

// Publicly re-export only the SSZ items this crate's API intends to expose
pub use ssz_generated::ssz::moho::{
    ExportContainer, ExportEntry, ExportState, MAX_PREDICATE_SIZE, MohoState,
};
