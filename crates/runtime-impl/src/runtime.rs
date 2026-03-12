//! Core runtime types.

use std::io::Cursor;

use borsh::BorshDeserialize;
use moho_runtime_interface::MohoProgram;
use moho_types::{MohoAttestation, MohoState, StateRefAttestation};

use crate::RuntimeInput;

pub fn compute_moho_attestation<P: MohoProgram>(
    input: RuntimeInput,
    spec: &P::Spec,
) -> MohoAttestation {
    let inner_pre_state = deserialize_borsh::<P::State>(input.inner_pre_state())
        .expect("runtime: deserialize pre state");
    let inner_input = deserialize_borsh::<P::StepInput>(input.input_payload())
        .expect("runtime: deserialize inner input");

    // Check the pre-state matches that in the moho pre-state.
    let computed_inner_state_root = P::compute_state_commitment(&inner_pre_state);
    assert_eq!(
        computed_inner_state_root,
        input.moho_pre_state().inner_state()
    );

    let step_output = P::process_transition(&inner_pre_state, spec, &inner_input);
    let inner_post_state = P::extract_post_state(&step_output);
    let inner_post_state_root = P::compute_state_commitment(inner_post_state);

    let next_predicate = match P::extract_next_predicate(&step_output) {
        Some(new_key) => new_key,
        None => input.moho_pre_state().next_predicate.clone(),
    };

    let export_state =
        P::compute_next_export_state(input.moho_pre_state().export_state.clone(), &step_output);
    let updated_moho_state = MohoState::new(inner_post_state_root, next_predicate, export_state);

    let previously_verified_state_ref = StateRefAttestation::new(
        P::extract_prev_reference(&inner_input),
        input.moho_pre_state().compute_commitment(),
    );
    let newly_verified_state_ref = StateRefAttestation::new(
        P::compute_input_reference(&inner_input),
        updated_moho_state.compute_commitment(),
    );
    MohoAttestation::new(previously_verified_state_ref, newly_verified_state_ref)
}

fn deserialize_borsh<T: BorshDeserialize>(buf: &[u8]) -> Result<T, borsh::io::Error> {
    let mut cur = Cursor::new(buf);
    borsh::from_reader::<_, T>(&mut cur)
}
