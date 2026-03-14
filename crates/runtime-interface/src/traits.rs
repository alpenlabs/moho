//! Traits used to describe an inner state transition.

use moho_types::{ExportState, InnerStateCommitment, StateReference};
use ssz::{Decode, Encode};
use strata_predicate::PredicateKey;

/// Trait implementation for the Moho program.
pub trait MohoProgram {
    /// The inner state.
    type State: Decode + Encode;

    /// Private input to process the next state.
    type StepInput: Decode + Encode;

    /// The specification type that defines program behavior and configuration.
    type Spec;

    /// Output after processing the step input
    type StepOutput;

    /// Computes the reference to the input state.
    fn compute_input_reference(input: &Self::StepInput) -> StateReference;

    /// Extracts the state reference to the input's previous input from it.
    fn extract_prev_reference(input: &Self::StepInput) -> StateReference;

    /// Computes the commitment to the inner state.
    fn compute_state_commitment(state: &Self::State) -> InnerStateCommitment;

    /// Computes the state transition from the input.
    ///
    /// # Panics
    ///
    /// Panics if the provided `pre_state`, `spec`, and `inp` violate the program invariant.
    fn process_transition(
        pre_state: &Self::State,
        spec: &Self::Spec,
        inp: &Self::StepInput,
    ) -> Self::StepOutput;

    /// Extracts the next inner predicate key from a step’s output.
    ///
    /// # Returns
    ///
    /// - `Some(PredicateKey)` if the inner predicate key has been updated.
    /// - `None` if there is no update to the inner predicate key.
    fn extract_next_predicate(output: &Self::StepOutput) -> Option<PredicateKey>;

    /// Extracts the inner state after a transition from the step’s output.
    fn extract_post_state(output: &Self::StepOutput) -> &Self::State;

    /// Computes the new exported state from the previous one and the step output.
    fn compute_next_export_state(prev: ExportState, output: &Self::StepOutput) -> ExportState;
}
