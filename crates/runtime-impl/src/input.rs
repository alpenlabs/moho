//! Runtime input.

use borsh::{BorshDeserialize, BorshSerialize};
use moho_types::{MohoState, MohoStateCommitment, StateReference};

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct RuntimeInput {
    /// Attestation for the pre-state.
    pre_state_ref: StateReference,

    /// Moho pre-state referring to `inner_pre_state`.
    moho_pre_state: MohoState,

    /// The inner pre-state that we compute the state transition on.
    inner_pre_state: Vec<u8>,

    /// The payload we're computing the state transition of.
    input_payload: Vec<u8>,

    /// Commitment to the post-state.
    post_state_commitment: MohoStateCommitment,
}

impl RuntimeInput {
    pub fn pre_state_ref(&self) -> &StateReference {
        &self.pre_state_ref
    }

    pub fn moho_pre_state(&self) -> &MohoState {
        &self.moho_pre_state
    }

    pub fn inner_pre_state(&self) -> &[u8] {
        &self.inner_pre_state
    }

    pub fn input_payload(&self) -> &[u8] {
        &self.input_payload
    }

    pub fn post_state_commitment(&self) -> &MohoStateCommitment {
        &self.post_state_commitment
    }

    pub fn into_pre_state(self) -> MohoState {
        self.moho_pre_state
    }
}
