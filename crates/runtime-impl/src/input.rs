//! Runtime input.

use moho_types::MohoState;
use ssz_derive::{Decode, Encode};

#[derive(Clone, Debug, Encode, Decode)]
pub struct RuntimeInput {
    /// Moho pre-state referring to `inner_pre_state`.
    moho_pre_state: MohoState,

    /// The inner pre-state that we compute the state transition on.
    inner_pre_state: Vec<u8>,

    /// The payload we're computing the state transition of.
    input_payload: Vec<u8>,
}

impl RuntimeInput {
    pub fn moho_pre_state(&self) -> &MohoState {
        &self.moho_pre_state
    }

    pub fn inner_pre_state(&self) -> &[u8] {
        &self.inner_pre_state
    }

    pub fn input_payload(&self) -> &[u8] {
        &self.input_payload
    }

    pub fn into_pre_state(self) -> MohoState {
        self.moho_pre_state
    }
}
