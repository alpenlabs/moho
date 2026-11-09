//! Core logic for computing a [`StepMohoAttestation`] from a single state transition step.
//!
//! This module contains [`compute_moho_attestation`], the main entry point for executing
//! an incremental state transition. It takes a [`RuntimeInput`] (containing the Moho
//! pre-state and SSZ-encoded inner state/input), runs the
//! [`MohoProgram`] transition logic, and returns a [`StepMohoAttestation`] — the public
//! parameter required by the recursive proof.
use moho_runtime_interface::MohoProgram;
use moho_types::{MohoState, StateRefAttestation, StepMohoAttestation};
use ssz::Decode;

use crate::RuntimeInput;

/// Computes a [`StepMohoAttestation`] for a single incremental state transition.
///
/// This is the main entry point for the Moho proof runtime. It:
///
/// 1. Deserializes the inner pre-state and step input from the [`RuntimeInput`].
/// 2. Verifies that the inner pre-state's commitment matches the one stored in the Moho pre-state
///    (ensuring consistency between the two state levels), and validates the Moho pre-state.
/// 3. Executes the program's state transition via [`MohoProgram::process_transition`].
/// 4. Constructs and validates the post-transition [`MohoState`] with the updated inner state
///    commitment, predicate, and export state.
/// 5. Returns a [`StepMohoAttestation`] binding the pre-state reference/commitment to the
///    post-state reference/commitment. This attestation serves as the public parameter for the
///    recursive proof.
///
/// # Panics
///
/// Panics if deserialization fails, if the inner pre-state commitment does not match
/// the commitment in the Moho pre-state, or if the pre- or post-transition [`MohoState`] fails
/// [`MohoState::validate`].
pub fn compute_moho_attestation<P: MohoProgram>(
    input: RuntimeInput,
    spec: &P::Spec,
) -> StepMohoAttestation {
    let inner_pre_state =
        P::State::from_ssz_bytes(input.inner_pre_state()).expect("runtime: deserialize pre state");
    let inner_input = deserialize_ssz::<P::StepInput>(input.input_payload())
        .expect("runtime: deserialize inner input");

    // Verify that the provided inner pre-state is consistent with the Moho pre-state
    // by checking that its commitment matches the one stored in `moho_pre_state`.
    let pre_inner_state_commitment = P::compute_state_commitment(&inner_pre_state);
    assert_eq!(
        pre_inner_state_commitment,
        input.moho_pre_state().inner_state(),
        "runtime: inner pre-state commitment does not match moho pre-state"
    );

    // SSZ decoding does not run `validate`. Checking every pre-state also covers genesis,
    // which no earlier step produced.
    input
        .moho_pre_state()
        .validate()
        .expect("runtime: invalid moho pre-state");

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
    post_moho_state
        .validate()
        .expect("runtime: invalid moho post-state");

    // Build the post-state half of the attestation.
    let post_state_attestation = StateRefAttestation::new(
        P::compute_input_reference(&inner_input),
        post_moho_state.compute_commitment(),
    );
    StepMohoAttestation::new(pre_state_attestation, post_state_attestation)
}

/// Deserializes an SSZ-encoded value from a byte slice.
fn deserialize_ssz<T: Decode>(buf: &[u8]) -> Result<T, ssz::DecodeError> {
    T::from_ssz_bytes(buf)
}

#[cfg(test)]
mod tests {
    use moho_types::{ExportContainer, ExportState, InnerStateCommitment, StateReference};
    use ssz::Encode;
    use strata_predicate::PredicateKey;

    use super::*;

    /// Program whose state and input are a single `u64`. It passes the export state through
    /// unchanged unless the input is [`DUPLICATE_EXPORT`].
    struct TestProgram;

    /// Step input that makes [`TestProgram`] return an export state with a repeated ID.
    const DUPLICATE_EXPORT: u64 = 1;

    impl MohoProgram for TestProgram {
        type State = u64;
        type StepInput = u64;
        type Spec = ();
        type StepOutput = (u64, u64);

        fn compute_input_reference(_input: &u64) -> StateReference {
            StateReference::from([1; 32])
        }

        fn extract_prev_reference(_input: &u64) -> StateReference {
            StateReference::from([0; 32])
        }

        fn compute_state_commitment(state: &u64) -> InnerStateCommitment {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&state.to_le_bytes());
            InnerStateCommitment::from(bytes)
        }

        fn process_transition(pre_state: &u64, _spec: &(), inp: &u64) -> (u64, u64) {
            (pre_state + 1, *inp)
        }

        fn extract_next_predicate(_output: &(u64, u64)) -> Option<PredicateKey> {
            None
        }

        fn extract_post_state(output: &(u64, u64)) -> &u64 {
            &output.0
        }

        fn compute_next_export_state(prev: ExportState, output: &(u64, u64)) -> ExportState {
            if output.1 == DUPLICATE_EXPORT {
                duplicate_export_state()
            } else {
                prev
            }
        }
    }

    /// `ExportState::new` rejects repeated IDs, so set the field directly, as SSZ decoding
    /// would.
    fn duplicate_export_state() -> ExportState {
        ExportState {
            containers: vec![ExportContainer::new(3), ExportContainer::new(3)]
                .try_into()
                .unwrap(),
        }
    }

    fn runtime_input(export_state: ExportState, step_input: u64) -> RuntimeInput {
        let pre_state = 0u64;
        let moho_pre_state = MohoState::new(
            TestProgram::compute_state_commitment(&pre_state),
            PredicateKey::always_accept(),
            export_state,
        );
        RuntimeInput::new(
            moho_pre_state,
            pre_state.as_ssz_bytes(),
            step_input.as_ssz_bytes(),
        )
    }

    #[test]
    fn accepts_unique_container_ids() {
        let export =
            ExportState::new(vec![ExportContainer::new(3), ExportContainer::new(4)]).unwrap();
        compute_moho_attestation::<TestProgram>(runtime_input(export, 0), &());
    }

    #[test]
    #[should_panic(expected = "runtime: invalid moho pre-state")]
    fn rejects_duplicate_ids_in_pre_state() {
        compute_moho_attestation::<TestProgram>(runtime_input(duplicate_export_state(), 0), &());
    }

    #[test]
    #[should_panic(expected = "runtime: invalid moho post-state")]
    fn rejects_duplicate_ids_in_post_state() {
        let export = ExportState::new(vec![]).unwrap();
        compute_moho_attestation::<TestProgram>(runtime_input(export, DUPLICATE_EXPORT), &());
    }
}
