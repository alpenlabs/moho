//! SSZ-encoded input provided to the runtime for computing a single state transition.

use moho_types::MohoState;
use ssz_derive::{Decode, Encode};

/// The input required to compute a single incremental state transition.
///
/// Contains the Moho-level pre-state, the borsh-encoded inner state, and the
/// borsh-encoded step input. The runtime deserializes these, runs the
/// [`MohoProgram`](moho_runtime_interface::MohoProgram) transition logic, and
/// produces a [`MohoAttestation`](moho_types::MohoAttestation).
#[derive(Clone, Debug, Encode, Decode)]
pub struct RuntimeInput {
    /// The [`MohoState`] before the transition. Contains the
    /// [`InnerStateCommitment`](moho_types::InnerStateCommitment) that
    /// `inner_pre_state` must match, along with the current predicate and
    /// export state.
    moho_pre_state: MohoState,

    /// Borsh-encoded inner state (`P::State`). The runtime verifies that its
    /// commitment matches `moho_pre_state.inner_state` before processing the
    /// transition.
    inner_pre_state: Vec<u8>,

    /// Borsh-encoded step input (`P::StepInput`) that drives the state
    /// transition.
    input_payload: Vec<u8>,
}

impl RuntimeInput {
    pub fn new(
        moho_pre_state: MohoState,
        inner_pre_state: Vec<u8>,
        input_payload: Vec<u8>,
    ) -> Self {
        Self {
            moho_pre_state,
            inner_pre_state,
            input_payload,
        }
    }

    /// Returns a reference to the Moho pre-state.
    pub fn moho_pre_state(&self) -> &MohoState {
        &self.moho_pre_state
    }

    /// Returns the borsh-encoded inner pre-state bytes.
    pub fn inner_pre_state(&self) -> &[u8] {
        &self.inner_pre_state
    }

    /// Returns the borsh-encoded step input bytes.
    pub fn input_payload(&self) -> &[u8] {
        &self.input_payload
    }

    /// Consumes self and returns the Moho pre-state.
    pub fn into_pre_state(self) -> MohoState {
        self.moho_pre_state
    }
}
