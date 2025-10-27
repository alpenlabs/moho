use moho_types::MohoState;
use zkaleido::ZkVmEnv;

use crate::{MohoError, MohoRecursiveOutput, MohoStateTransition, program::MohoRecursiveInput};

/// Entry point for processing recursive Moho proofs within a zkVM environment.
///
/// This function reads a [`MohoRecursiveInput`] from the zkVM, performs verification
/// of the proof components and chaining of the corresponding states, then commits the resulting
/// complete state transition along with the Moho predicate key back to the zkVM.
///
/// # Arguments
///
/// * `zkvm` - A zkVM environment that implements [`ZkVmEnv`] for reading input data and committing
///   output data using Borsh serialization
///
/// # Type Parameters
///
/// * `V` - A verifier type that implements `ZkVmVerifier + BorshSerialize + BorshDeserialize` for
///   proof verification operations
///
/// # Panics
///
/// Panics if proof verification or chaining fails, as this function calls
/// `unwrap()` on the result from `verify_and_chain_transition`. Consider using
/// `verify_and_chain_transition` directly for error handling.
pub fn process_recursive_moho_proof(zkvm: &impl ZkVmEnv) {
    let input: MohoRecursiveInput = zkvm.read_borsh();
    let moho_predicate = input.moho_predicate.clone();
    let full_transition = verify_and_chain_transition(input).unwrap();
    let output = MohoRecursiveOutput {
        moho_predicate,
        transition: full_transition,
    };
    zkvm.commit_borsh(&output);
}

/// Verifies the inductive and recursive Moho proofs and chains the corresponding states produce a
/// complete state transition.
///
/// This function performs the following steps in order:
/// 1. Verifies that the provided step predicate key is included in the current Moho state Merkle
///    commitment.
/// 2. Verifies the incremental proof against the given predicate key.
/// 3. If a previous recursive proof exists, verifies it and chains its state transition with the
///    current one.
///
/// # Returns
///
/// A `Result` containing the full `MohoStateTransition` if verification succeeds,
/// or a `MohoError` indicating the first failure encountered.
pub fn verify_and_chain_transition(
    input: MohoRecursiveInput,
) -> Result<MohoStateTransition, MohoError> {
    // 1: Ensure the incremental proof predicate key is part of the Moho state Merkle root.
    let next_predicate_hash = MohoState::compute_next_predicate_ssz_root(&input.step_predicate);
    if !MohoState::verify_proof_against_commitment(
        input
            .incremental_step_proof
            .transition()
            .from()
            .commitment(),
        &input.step_predicate_merkle_proof,
        &next_predicate_hash,
    ) {
        // Fail early if the Merkle proof is invalid
        return Err(MohoError::InvalidMerkleProof);
    }

    // 2: Verify the correctness of the incremental step proof itself.
    input
        .incremental_step_proof
        .verify(&input.step_predicate)
        .map_err(MohoError::InvalidIncrementalProof)?;

    // Extract the incremental step transition and proof
    let (step_t, _step_proof) = input.incremental_step_proof.into_parts();

    // Step 3: Handle previous recursive proof and previous and new state chaining
    match input.prev_recursive_proof {
        // No previous proof: return the incremental step transition directly
        None => Ok(step_t),

        // Previous proof exists: verify and chain with current step
        Some(prev_proof) => {
            // Verify the previous recursive proof against the Moho predicate
            prev_proof
                .verify(&input.moho_predicate)
                .map_err(MohoError::InvalidRecursiveProof)?;

            // Extract the previous state transition
            let (prev_t, _proof) = prev_proof.into_parts();

            // Chain the previous transition with the current step transition
            prev_t
                .chain(step_t)
                .map_err(|e| MohoError::InvalidMohoChain(Box::new(e)))
        }
    }
}

#[cfg(test)]
mod tests {
    use moho_types::{
        ExportState, InnerStateCommitment, MohoState, MohoStateCommitment, StateRefAttestation,
        StateReference,
    };
    use strata_predicate::PredicateKey;
    use zkaleido::Proof;

    use super::*;
    use crate::transition::{MohoTransitionWithProof, Transition};

    fn create_state(id: u8, predicate: PredicateKey) -> MohoState {
        let inner = InnerStateCommitment::new([id; 32]);
        let export = ExportState::new(vec![]);
        MohoState::new(inner, predicate, export)
    }

    fn create_commitment(id: u8) -> MohoStateCommitment {
        let predicate = PredicateKey::always_accept();
        create_state(id, predicate).compute_commitment()
    }

    fn create_attestation(id: u8) -> StateRefAttestation {
        let ref_ = StateReference::new([id; 32]);
        let commit = create_commitment(id);
        StateRefAttestation::new(ref_, commit)
    }

    fn create_transition(from: u8, to: u8) -> MohoStateTransition {
        Transition::new(create_attestation(from), create_attestation(to))
    }

    // Creates recursive proof with Moho verifier
    fn create_recursive_proof(from: u8, to: u8) -> MohoTransitionWithProof {
        let t = create_transition(from, to);
        let proof = Proof::new("Moho".as_bytes().to_vec());
        MohoTransitionWithProof::new(t, proof)
    }

    // Creates step proof with ASM verifier
    fn create_step_proof(from: u8, to: u8) -> MohoTransitionWithProof {
        let t = create_transition(from, to);
        let proof = Proof::new("ASM".as_bytes().to_vec());
        MohoTransitionWithProof::new(t, proof)
    }

    fn create_input(from: u8, to: u8, prev: Option<(u8, u8)>) -> MohoRecursiveInput {
        let moho_predicate = PredicateKey::always_accept();
        let step_predicate = PredicateKey::always_accept();

        let step_proof = create_step_proof(from, to);
        let prev_proof = prev.map(|(f, t)| create_recursive_proof(f, t));

        let merkle_proof =
            create_state(from, step_predicate.clone()).generate_next_predicate_proof();

        MohoRecursiveInput {
            moho_predicate,
            prev_recursive_proof: prev_proof,
            incremental_step_proof: step_proof,
            step_predicate,
            step_predicate_merkle_proof: merkle_proof,
        }
    }

    #[test]
    fn test_verify_and_chain_transition_success() {
        // Test basic transition without previous proof
        let inp = create_input(1, 2, None);
        let expected = create_step_proof(1, 2);
        let result = verify_and_chain_transition(inp).unwrap();
        assert_eq!(&result, expected.transition());

        // Test with different state IDs
        let inp = create_input(10, 20, None);
        let expected = create_step_proof(10, 20);
        let result = verify_and_chain_transition(inp).unwrap();
        assert_eq!(&result, expected.transition());
    }

    #[test]
    fn test_verify_and_chain_transition_with_previous_proof_success() {
        // Test chaining: previous (1->2) + step (2->3) = full (1->3)
        let inp = create_input(2, 3, Some((1, 2)));
        let expected = create_step_proof(1, 3);
        let result = verify_and_chain_transition(inp).unwrap();
        assert_eq!(&result, expected.transition());

        // Test longer chain: previous (1->3) + step (3->10) = full (1->10)
        let inp = create_input(3, 10, Some((1, 3)));
        let expected = create_step_proof(1, 10);
        let result = verify_and_chain_transition(inp).unwrap();
        assert_eq!(&result, expected.transition());
    }

    #[test]
    fn test_verify_and_chain_transition_invalid_chain() {
        // Test invalid chain: previous ends at 2, step starts at 3 (gap)
        let inp = create_input(3, 5, Some((1, 2)));
        let result = verify_and_chain_transition(inp);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MohoError::InvalidMohoChain(_)
        ));
    }

    #[test]
    fn test_verify_and_chain_transition_invalid_merkle_proof() {
        // Test with wrong predicate - should fail Merkle proof check
        let mut inp = create_input(2, 3, None);
        inp.step_predicate = PredicateKey::never_accept();

        let result = verify_and_chain_transition(inp.clone());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MohoError::InvalidMerkleProof));

        // Test with correct predicate - should succeed
        inp.step_predicate = PredicateKey::always_accept();
        let expected = create_step_proof(2, 3);
        let result = verify_and_chain_transition(inp).unwrap();
        assert_eq!(&result, expected.transition());
    }

    #[test]
    fn test_verify_and_chain_transition_invalid_incremental_proof() {
        // Test with invalid step proof - should fail verification
        // Create a proper input with never_accept predicate from the start
        let never_accept = PredicateKey::never_accept();

        // Create state and attestation with never_accept predicate
        let from_state = create_state(1, never_accept.clone());
        let from_commitment = from_state.compute_commitment();
        let from_ref = StateReference::new([1; 32]);
        let from_attestation = StateRefAttestation::new(from_ref, from_commitment);

        let to_attestation = create_attestation(2);
        let transition = Transition::new(from_attestation, to_attestation);
        let step_proof =
            MohoTransitionWithProof::new(transition, Proof::new("ASM".as_bytes().to_vec()));

        let merkle_proof = from_state.generate_next_predicate_proof();

        let inp = MohoRecursiveInput {
            moho_predicate: PredicateKey::always_accept(),
            prev_recursive_proof: None,
            incremental_step_proof: step_proof,
            step_predicate: never_accept,
            step_predicate_merkle_proof: merkle_proof,
        };

        let result = verify_and_chain_transition(inp);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MohoError::InvalidIncrementalProof(_)
        ));
    }

    #[test]
    fn test_verify_and_chain_transition_invalid_recursive_proof() {
        // Test with invalid previous proof - should fail verification
        // Use never_accept predicate to ensure verification fails
        let mut inp = create_input(2, 3, Some((1, 2)));
        inp.moho_predicate = PredicateKey::never_accept();

        let result = verify_and_chain_transition(inp);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MohoError::InvalidRecursiveProof(_)
        ));
    }

    #[test]
    fn test_verify_and_chain_transition_edge_case_same_state() {
        // Test transition from state to itself - currently allowed
        let inp = create_input(5, 5, None);
        let result = verify_and_chain_transition(inp);
        assert!(result.is_ok());
    }
}
