//! Core runtime types.

use moho_runtime_interface::MohoProgram;
use moho_types::{
    ExportContainer, ExportState, MohoAttestation, MohoState, MohoStateCommitment, ProofSystem,
    StateRefAttestation, StateReference,
};

/// Verifies a new state ref attestation is a consistent extension of a previous
/// state attestation.
///
/// # Panics
///
/// if it's incorrect
pub fn verify_relation<P: MohoProgram>(
    prev_state_attestation: &StateRefAttestation,
    next_attestation: &StateRefAttestation,
    pre_moho_state: &MohoState,
    pre_inner_state: &P::State,
    input: &P::StepInput,
) {
    // Compute the transition.
    let post_state = compute_transition::<P>(
        prev_state_attestation.reference(),
        pre_moho_state,
        pre_inner_state,
        input,
    );

    // Checks the input refs match.
    let input_ref = P::compute_input_reference(input);
    assert_eq!(
        input_ref,
        *next_attestation.reference(),
        "runtime: input ref mismatch"
    );

    // Checks the state commitments match.
    let post_state_commitment = compute_moho_state_commitment(&post_state);
    assert_eq!(
        post_state_commitment,
        *next_attestation.commitment(),
        "runtime: post state commitment match"
    );
}

/// Computes and verifies a transition against an attestation we are trying to
/// prove.
pub fn compute_transition<P: MohoProgram>(
    pre_state_ref: &StateReference,
    pre_moho_state: &MohoState,
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
    let post_state = P::process_transition(pre_inner_state, input);
    let post_outer_state = compute_wrapping_moho_state::<P>(&post_state);

    post_outer_state
}

/// Computes the state commitment to a moho state.
fn compute_moho_state_commitment(state: &MohoState) -> MohoStateCommitment {
    unimplemented!()
}

/// Computes the exported Moho state from the inner state, also checking the
/// verification key and export correctness.
fn compute_wrapping_moho_state<P: MohoProgram>(state: &P::State) -> MohoState {
    let inner_root = P::compute_state_commitment(state);

    let next_vk = P::extract_next_vk(state);

    let export_state = P::extract_export_state(state);
    if !check_export_state_structure(&export_state) {
        panic!("runtime: invalid export state structure");
    }

    MohoState::new(inner_root, next_vk, export_state)
}

/// Performs structural sanity checks on the export state structure.
fn check_export_state_structure(estate: &ExportState) -> bool {
    for pair in estate.containers().windows(2) {
        let a = &pair[0];
        let b = &pair[1];

        // b's ID always has to be strictly greater than a's ID
        if a.container_id() >= b.container_id() {
            return false;
        }
    }

    for c in estate.containers().iter() {
        if !check_export_cont_structure(c) {
            return false;
        }
    }

    // TODO payload size checks

    true
}

fn check_export_cont_structure(cont: &ExportContainer) -> bool {
    for pair in cont.entries().windows(2) {
        let a = &pair[0];
        let b = &pair[1];

        if a.entry_id() >= b.entry_id() {
            return false;
        }
    }

    // TODO payload size checks

    true
}
