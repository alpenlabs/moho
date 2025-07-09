//! Core runtime types.

use std::io::Cursor;

use borsh::BorshDeserialize;
use moho_runtime_interface::MohoProgram;
use moho_types::{
    ExportContainer, ExportState, MAX_EXPORT_CONTAINERS, MAX_EXPORT_ENTRIES, MAX_PAYLOAD_SIZE,
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

    // Compute and verify the transition attestation.
    let post_ref_att = compute_transition_attestation::<P>(
        input.pre_state_ref(),
        input.moho_pre_state(),
        &inner_pre_state,
        &inner_input,
    );

    // Check the attestation matches the reference in the input.
    assert_eq!(
        input.post_state_commitment(),
        post_ref_att.commitment(),
        "runtime: post state commitment match"
    );

    // Assemble the final attestation.
    let pre_commitment = compute_moho_state_commitment(input.moho_pre_state());
    let pre_ref_att = StateRefAttestation::new(*input.pre_state_ref(), pre_commitment);
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
    pre_moho_state: &MohoState,
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
    let (post_state, step_output) = P::process_transition(pre_inner_state, input);
    compute_wrapping_moho_state::<P>(&post_state, &step_output)
}

/// Computes the state commitment to a moho state.
fn compute_moho_state_commitment(_state: &MohoState) -> MohoStateCommitment {
    // TODO SSZ merkle hashing
    unimplemented!()
}

/// Computes the exported Moho state from the inner state, also checking the
/// verification key and export correctness.
fn compute_wrapping_moho_state<P: MohoProgram>(
    state: &P::State,
    step_output: &P::StepOutput,
) -> MohoState {
    let inner_root = P::compute_state_commitment(state);

    let next_vk = P::extract_next_vk(step_output);

    let export_state = P::extract_export_state(step_output);
    if !check_export_state_structure(&export_state) {
        panic!("runtime: invalid export state structure");
    }

    MohoState::new(inner_root, next_vk, export_state)
}

/// Performs structural sanity checks on the export state structure.
fn check_export_state_structure(estate: &ExportState) -> bool {
    if estate.containers().len() > MAX_EXPORT_CONTAINERS {
        return false;
    }

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

    true
}

fn check_export_cont_structure(cont: &ExportContainer) -> bool {
    if cont.entries().len() > MAX_EXPORT_ENTRIES {
        return false;
    }

    if cont.common_payload().len() > MAX_PAYLOAD_SIZE {
        return false;
    }

    for pair in cont.entries().windows(2) {
        let a = &pair[0];
        let b = &pair[1];

        if a.entry_id() >= b.entry_id() {
            return false;
        }
    }

    for e in cont.entries() {
        if e.payload().len() > MAX_PAYLOAD_SIZE {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use moho_types::{ExportContainer, ExportEntry, ExportState};

    use super::*;

    fn create_valid_export_state() -> ExportState {
        let entry1 = ExportEntry::new(1, vec![1, 2, 3]);
        let entry2 = ExportEntry::new(2, vec![4, 5, 6]);
        let container1 = ExportContainer::new(1, vec![7, 8, 9], vec![entry1, entry2]);

        let entry3 = ExportEntry::new(1, vec![10, 11, 12]);
        let container2 = ExportContainer::new(2, vec![13, 14, 15], vec![entry3]);

        ExportState::new(vec![container1, container2])
    }

    #[test]
    fn test_check_export_state_structure_valid() {
        let export_state = create_valid_export_state();
        assert!(check_export_state_structure(&export_state));
    }

    #[test]
    fn test_check_export_state_structure_too_many_containers() {
        let mut containers = Vec::new();
        for i in 0..=MAX_EXPORT_CONTAINERS {
            let entry = ExportEntry::new(1, vec![1, 2, 3]);
            let container = ExportContainer::new(i as u16, vec![], vec![entry]);
            containers.push(container);
        }
        let export_state = ExportState::new(containers);
        assert!(!check_export_state_structure(&export_state));
    }

    #[test]
    fn test_check_export_state_structure_unsorted_containers() {
        let entry1 = ExportEntry::new(1, vec![1, 2, 3]);
        let container1 = ExportContainer::new(2, vec![], vec![entry1]);

        let entry2 = ExportEntry::new(1, vec![4, 5, 6]);
        let container2 = ExportContainer::new(1, vec![], vec![entry2]); // ID 1 < 2, wrong order

        let export_state = ExportState::new(vec![container1, container2]);
        assert!(!check_export_state_structure(&export_state));
    }

    #[test]
    fn test_check_export_state_structure_duplicate_container_ids() {
        let entry1 = ExportEntry::new(1, vec![1, 2, 3]);
        let container1 = ExportContainer::new(1, vec![], vec![entry1]);

        let entry2 = ExportEntry::new(1, vec![4, 5, 6]);
        let container2 = ExportContainer::new(1, vec![], vec![entry2]); // Duplicate ID

        let export_state = ExportState::new(vec![container1, container2]);
        assert!(!check_export_state_structure(&export_state));
    }

    #[test]
    fn test_check_export_state_structure_empty() {
        let empty_export_state = ExportState::new(vec![]);
        assert!(check_export_state_structure(&empty_export_state));
    }

    #[test]
    fn test_check_export_cont_structure_valid() {
        let entry1 = ExportEntry::new(1, vec![1, 2, 3]);
        let entry2 = ExportEntry::new(2, vec![4, 5, 6]);
        let container = ExportContainer::new(1, vec![7, 8, 9], vec![entry1, entry2]);
        assert!(check_export_cont_structure(&container));
    }

    #[test]
    fn test_check_export_cont_structure_too_many_entries() {
        let mut entries = Vec::new();
        for i in 0..=MAX_EXPORT_ENTRIES {
            let entry = ExportEntry::new(i as u32, vec![1, 2, 3]);
            entries.push(entry);
        }
        let container = ExportContainer::new(1, vec![], entries);
        assert!(!check_export_cont_structure(&container));
    }

    #[test]
    fn test_check_export_cont_structure_common_payload_too_large() {
        let entry = ExportEntry::new(1, vec![1, 2, 3]);
        let large_payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let container = ExportContainer::new(1, large_payload, vec![entry]);
        assert!(!check_export_cont_structure(&container));
    }

    #[test]
    fn test_check_export_cont_structure_unsorted_entries() {
        let entry1 = ExportEntry::new(2, vec![1, 2, 3]);
        let entry2 = ExportEntry::new(1, vec![4, 5, 6]); // ID 1 < 2, wrong order
        let container = ExportContainer::new(1, vec![], vec![entry1, entry2]);
        assert!(!check_export_cont_structure(&container));
    }

    #[test]
    fn test_check_export_cont_structure_duplicate_entry_ids() {
        let entry1 = ExportEntry::new(1, vec![1, 2, 3]);
        let entry2 = ExportEntry::new(1, vec![4, 5, 6]); // Duplicate ID
        let container = ExportContainer::new(1, vec![], vec![entry1, entry2]);
        assert!(!check_export_cont_structure(&container));
    }

    #[test]
    fn test_check_export_cont_structure_entry_payload_too_large() {
        let large_payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let entry = ExportEntry::new(1, large_payload);
        let container = ExportContainer::new(1, vec![], vec![entry]);
        assert!(!check_export_cont_structure(&container));
    }

    #[test]
    fn test_check_export_cont_structure_empty_entries() {
        let container = ExportContainer::new(1, vec![1, 2, 3], vec![]);
        assert!(check_export_cont_structure(&container));
    }

    #[test]
    fn test_check_export_cont_structure_max_payload_size() {
        let entry = ExportEntry::new(1, vec![0u8; MAX_PAYLOAD_SIZE]);
        let container = ExportContainer::new(1, vec![0u8; MAX_PAYLOAD_SIZE], vec![entry]);
        assert!(check_export_cont_structure(&container));
    }
}
