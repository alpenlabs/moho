//! Core runtime types.

use std::io::Cursor;

use borsh::BorshDeserialize;
use moho_runtime_interface::MohoProgram;
use moho_types::{
    MohoAttestation, MohoState, MohoStateCommitment, StateRefAttestation, StateReference,
};

use crate::RuntimeInput;

/// Verifies the runtime's input.  Returns a new [`MohoAttestation`] for the
/// state transition.
///
/// # Panics
///
/// If it's incorrect.
pub fn verify_input<P: MohoProgram>(input: RuntimeInput) -> MohoAttestation {
    let inner_pre_state = deserialize_borsh::<P::State>(input.inner_pre_state())
        .expect("runtime: deserialize pre state");
    let inner_input = deserialize_borsh::<P::StepInput>(input.input_payload())
        .expect("runtime: deserialize inner input");

    let pre_state_ref = *input.pre_state_ref();
    let pre_commitment = compute_moho_state_commitment(input.moho_pre_state());
    let pre_ref_att = StateRefAttestation::new(pre_state_ref, pre_commitment);

    let post_commitment = *input.post_state_commitment();

    // Compute and verify the transition attestation.
    let post_ref_att = compute_transition_attestation::<P>(
        &pre_state_ref,
        input.into_pre_state(),
        &inner_pre_state,
        &inner_input,
    );

    // Check the attestation matches the reference in the input.
    assert_eq!(
        &post_commitment,
        post_ref_att.commitment(),
        "runtime: post state commitment match"
    );

    // Assemble the final attestation.
    MohoAttestation::new(pre_ref_att, post_ref_att)
}

fn deserialize_borsh<T: BorshDeserialize>(buf: &[u8]) -> Result<T, borsh::io::Error> {
    let mut cur = Cursor::new(buf);
    borsh::from_reader::<_, T>(&mut cur)
}

/// Verifies an input is a valid extension of a previous state reference and
/// state, returning an attestation to that new state.
///
/// # Panics
///
/// If it's incorrect.
fn compute_transition_attestation<P: MohoProgram>(
    pre_state_ref: &StateReference,
    pre_moho_state: MohoState,
    pre_inner_state: &P::State,
    input: &P::StepInput,
) -> StateRefAttestation {
    // Check the input's parent extends it properly.
    let input_ref = P::compute_input_reference(input);
    let prev_input_ref = P::extract_prev_reference(input);
    assert_eq!(
        prev_input_ref, *pre_state_ref,
        "runtime: input parent mismatch"
    );

    // Compute the transition.
    let post_state = compute_transition::<P>(pre_state_ref, pre_moho_state, pre_inner_state, input);

    // Construct the attestation.
    let post_state_commitment = compute_moho_state_commitment(&post_state);
    StateRefAttestation::new(input_ref, post_state_commitment)
}

/// Computes and verifies a transition against an attestation we are trying to
/// prove.
pub fn compute_transition<P: MohoProgram>(
    pre_state_ref: &StateReference,
    pre_moho_state: MohoState,
    pre_inner_state: &P::State,
    input: &P::StepInput,
) -> MohoState {
    // Check the pre-state matches that in the moho pre-state.
    let computed_inner_state_root = P::compute_state_commitment(pre_inner_state);
    assert_eq!(
        computed_inner_state_root,
        pre_moho_state.inner_state(),
        "runtime: input moho state mismatch"
    );

    // Check the input parent matches the pre-state ref so that we ensure it's
    // building a chain correctly.
    let input_parent_ref = P::extract_prev_reference(input);
    assert_eq!(
        input_parent_ref, *pre_state_ref,
        "runtime: input parent ref mismatch"
    );

    // Compute the new state and wrap it.
    let output = P::process_transition(pre_inner_state, input);
    compute_wrapping_moho_state::<P>(pre_moho_state, &output)
}

/// Computes the state commitment to a moho state.
fn compute_moho_state_commitment(state: &MohoState) -> MohoStateCommitment {
    state.compute_commitment()
}

/// Computes the exported Moho state from the inner state, also checking the
/// predicate key and export correctness.
fn compute_wrapping_moho_state<P: MohoProgram>(
    moho_state: MohoState,
    step_output: &P::StepOutput,
) -> MohoState {
    let post_inner_state = P::extract_post_state(step_output);
    let post_inner_root = P::compute_state_commitment(post_inner_state);

    // Determine the next predicate key: use the updated key if available, otherwise fall
    // back to the previous one
    let next_predicate = match P::extract_next_predicate(step_output) {
        Some(predicate) => predicate,
        None => moho_state.next_predicate(),
    };

    let new_export_state = P::compute_export_state(moho_state.into_export_state(), step_output);

    let new_moho_state = MohoState::new(post_inner_root, next_predicate, new_export_state);

    new_moho_state
}
