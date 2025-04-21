//! Traits used to describe an inner state transition.
//!
//! This module is using borsh as a transitive measure.

use borsh::{BorshDeserialize, BorshSerialize};
use moho_types::{ExportState, InnerStateCommitment, InnerVerificationKey, StateReference};

/// Trait implementation for the Moho program.
pub trait MohoProgram {
    /// The inner state.
    type State: BorshDeserialize + BorshSerialize;

    /// Private input to process the next state.
    type StepInput: BorshDeserialize + BorshSerialize;

    /// Computes the reference to the input state.
    fn compute_input_reference(input: &Self::StepInput) -> StateReference;

    /// Extracts the state reference to the input's previous input from it.
    fn extract_prev_reference(input: &Self::StepInput) -> StateReference;

    /// Computes the commitment to the inner state.
    fn compute_state_commitment(state: &Self::State) -> InnerStateCommitment;

    /// Computes the state transition from the input.
    ///
    /// If this returns error, proving fails.
    // TODO make result type
    fn process_transition(pre_state: &Self::State, inp: &Self::StepInput) -> Self::State;

    /// Extracts the next vk from the state.
    fn extract_next_vk(state: &Self::State) -> InnerVerificationKey;

    /// Extracts the exported output from the state.
    fn extract_export_state(state: &Self::State) -> ExportState;
}
