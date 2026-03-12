//! Core logic for computing a [`MohoAttestation`] from a single state transition step.
//!
//! This module contains [`compute_moho_attestation`], the main entry point for executing
//! an incremental state transition. It takes a [`RuntimeInput`] (containing the Moho
//! pre-state and borsh-encoded inner state/input), runs the
//! [`MohoProgram`] transition logic, and returns a [`MohoAttestation`] — the public
//! parameter required by the recursive proof.

use std::io::Cursor;

use borsh::BorshDeserialize;
use moho_runtime_interface::MohoProgram;
use moho_types::{MohoAttestation, MohoState, StateRefAttestation};

use crate::RuntimeInput;

/// Computes a [`MohoAttestation`] for a single incremental state transition.
///
/// This is the main entry point for the Moho proof runtime. It:
///
/// 1. Deserializes the inner pre-state and step input from the [`RuntimeInput`].
/// 2. Verifies that the inner pre-state's commitment matches the one stored in the Moho pre-state
///    (ensuring consistency between the two state levels).
/// 3. Executes the program's state transition via [`MohoProgram::process_transition`].
/// 4. Constructs the post-transition [`MohoState`] with the updated inner state commitment,
///    predicate, and export state.
/// 5. Returns a [`MohoAttestation`] binding the pre-state reference/commitment to the post-state
///    reference/commitment. This attestation serves as the public parameter for the recursive
///    proof.
///
/// # Panics
///
/// Panics if deserialization fails or if the inner pre-state commitment does not match
/// the commitment in the Moho pre-state.
pub fn compute_moho_attestation<P: MohoProgram>(
    input: RuntimeInput,
    spec: &P::Spec,
) -> MohoAttestation {
    let inner_pre_state = deserialize_borsh::<P::State>(input.inner_pre_state())
        .expect("runtime: deserialize pre state");
    let inner_input = deserialize_borsh::<P::StepInput>(input.input_payload())
        .expect("runtime: deserialize inner input");

    // Verify that the provided inner pre-state is consistent with the Moho pre-state
    // by checking that its commitment matches the one stored in `moho_pre_state`.
    let pre_inner_state_commitment = P::compute_state_commitment(&inner_pre_state);
    assert_eq!(
        pre_inner_state_commitment,
        input.moho_pre_state().inner_state(),
        "runtime: inner pre-state commitment does not match moho pre-state"
    );

    // Execute the inner state transition.
    let step_output = P::process_transition(&inner_pre_state, spec, &inner_input);

    // Compute the post-transition inner state commitment.
    let inner_post_state = P::extract_post_state(&step_output);
    let post_inner_state_commitment = P::compute_state_commitment(inner_post_state);

    // Build the pre-state half of the attestation before consuming the input,
    // so we can move `moho_pre_state` fields without cloning.
    let pre_state_attestation = StateRefAttestation::new(
        P::extract_prev_reference(&inner_input),
        input.moho_pre_state().compute_commitment(),
    );

    // Destructure the owned moho pre-state to avoid cloning.
    let MohoState {
        next_predicate: pre_next_predicate,
        export_state: pre_export_state,
        ..
    } = input.into_pre_state();

    // Determine the next predicate: use updated key if the transition produced one,
    // otherwise carry forward the current predicate.
    let next_predicate = match P::extract_next_predicate(&step_output) {
        Some(new_key) => new_key,
        None => pre_next_predicate,
    };

    // Compute the updated export state and assemble the post-transition MohoState.
    let export_state = P::compute_next_export_state(pre_export_state, &step_output);
    let post_moho_state = MohoState::new(post_inner_state_commitment, next_predicate, export_state);

    // Build the post-state half of the attestation.
    let post_state_attestation = StateRefAttestation::new(
        P::compute_input_reference(&inner_input),
        post_moho_state.compute_commitment(),
    );
    MohoAttestation::new(pre_state_attestation, post_state_attestation)
}

/// Deserializes a borsh-encoded value from a byte slice.
fn deserialize_borsh<T: BorshDeserialize>(buf: &[u8]) -> Result<T, borsh::io::Error> {
    let mut cur = Cursor::new(buf);
    borsh::from_reader::<_, T>(&mut cur)
}
