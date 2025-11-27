//! moho types

pub mod errors;
mod relation;
mod state;

pub use errors::ExportStateError;
pub use relation::{MohoAttestation, StateRefAttestation};

// Include generated SSZ types from build.rs output
#[allow(
    clippy::all,
    unreachable_pub,
    clippy::allow_attributes,
    reason = "generated code"
)]
mod ssz_generated {
    include!(concat!(env!("OUT_DIR"), "/generated_ssz.rs"));
}

// Publicly re-export only the SSZ items this crate's API intends to expose
pub use ssz_generated::ssz::moho::{
    ExportContainer, ExportState, InnerStateCommitment, MohoState, MohoStateCommitment,
    StateReference,
};
