use borsh::{BorshDeserialize, BorshSerialize};
use moho_types::{MerkleTree, MohoState};
use zkaleido::{VerifyingKey, ZkVmEnv, ZkVmVerifier};

use crate::{MohoError, MohoStateTransition, program::MohoRecursiveInput};

/// Entry point for processing recursive Moho proofs within a zkVM environment.
///
/// This function reads a [`MohoRecursiveInput`] from the zkVM, performs verification
/// of the proof components and chaining of the corresponding states, then commits the resulting
/// complete state transition back to the zkVM.
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
pub fn process_recursive_moho_proof<V: ZkVmVerifier + BorshSerialize + BorshDeserialize>(
    zkvm: &impl ZkVmEnv,
) {
    let input: MohoRecursiveInput<V> = zkvm.read_borsh();
    let full_transition = verify_and_chain_transition(input).unwrap();
    zkvm.commit_borsh(&full_transition);
}

/// Verifies the inductive and recursive Moho proofs and chains the corresponding states produce a
/// complete state transition.
///
/// This function performs the following steps in order:
/// 1. Verifies that the provided step verification key (VK) is included in the current Moho state
///    Merkle commitment.
/// 2. Verifies the incremental proof against the given VK.
/// 3. If a previous recursive proof exists, verifies it and chains its state transition with the
///    current one.
///
/// # Returns
///
/// A `Result` containing the full `MohoStateTransition` if verification succeeds,
/// or a `MohoError` indicating the first failure encountered.
pub fn verify_and_chain_transition<V: ZkVmVerifier + BorshSerialize + BorshDeserialize>(
    input: MohoRecursiveInput<V>,
) -> Result<MohoStateTransition, MohoError> {
    // 1: Ensure the incremental proof VK is part of the Moho state Merkle root.

    // REVIEW: Right now MohoState includes VerifyingKey and the struct itself is not generic,
    // but we have made the MohoInput generic. We should make that consistent, but I'm not sure
    // on the best approach
    let wrapped_step_proof_vk =
        VerifyingKey::new(borsh::to_vec(&input.step_proof_verifier).unwrap());
    let next_vk_hash = MerkleTree::hash_serializable(&wrapped_step_proof_vk);
    if !MohoState::verify_proof_against_commitment(
        input
            .incremental_step_proof
            .transition()
            .from()
            .commitment(),
        &input.step_vk_merkle_proof,
        &next_vk_hash,
    ) {
        // Fail early if the Merkle proof is invalid
        return Err(MohoError::InvalidMerkleProof);
    }

    // 2: Verify the correctness of the incremental step proof itself.
    input
        .incremental_step_proof
        .verify(&input.step_proof_verifier)
        .map_err(MohoError::InvalidIncrementalProof)?;

    // Extract the incremental step transition and proof
    let (step_t, _step_proof) = input.incremental_step_proof.into_parts();

    // Step 3: Handle previous recursive proof and previous and new state chaining
    match input.prev_recursive_proof {
        // No previous proof: return the incremental step transition directly
        None => Ok(step_t),

        // Previous proof exists: verify and chain with current step
        Some(prev_proof) => {
            // Verify the previous recursive proof against the Moho VK
            prev_proof
                .verify(&input.moho_verifier)
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
    use borsh::{BorshDeserialize, BorshSerialize};
    use moho_types::{
        ExportState, InnerStateCommitment, MohoState, MohoStateCommitment, StateRefAttestation,
        StateReference,
    };
    use zkaleido::{Proof, ProofReceipt, VerifyingKey, ZkVmError, ZkVmVerifier};

    use super::*;
    use crate::transition::{MohoTransitionWithProof, Transition};

    /// Mock verifier for testing proof verification logic.
    ///
    /// This verifier compares proof bytes against its internal ID string.
    /// It succeeds when proof bytes match the ID, fails otherwise.
    #[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
    struct MockVerifier {
        id: String,
    }

    impl MockVerifier {
        fn new(id: String) -> Self {
            Self { id }
        }

        fn to_vk(&self) -> VerifyingKey {
            VerifyingKey::new(borsh::to_vec(&MockVerifier::new("ASM".to_string())).unwrap())
        }
    }

    impl ZkVmVerifier for MockVerifier {
        fn verify(&self, receipt: &ProofReceipt) -> Result<(), ZkVmError> {
            if receipt.proof().as_bytes() != self.id.as_bytes() {
                Err(ZkVmError::ExecutionError(
                    "Mock verification failed".to_string(),
                ))
            } else {
                Ok(())
            }
        }
    }

    fn create_state(id: u8, vk: VerifyingKey) -> MohoState {
        let inner = InnerStateCommitment::new([id; 32]);
        let export = ExportState::new(vec![]);
        MohoState::new(inner, vk, export)
    }

    fn create_commitment(id: u8) -> MohoStateCommitment {
        let vk = MockVerifier::new("ASM".to_string()).to_vk();
        create_state(id, vk).compute_commitment()
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

    fn create_input(from: u8, to: u8, prev: Option<(u8, u8)>) -> MohoRecursiveInput<MockVerifier> {
        let moho_v = MockVerifier::new("Moho".to_string());
        let step_v = MockVerifier::new("ASM".to_string());

        let step_proof = create_step_proof(from, to);
        let prev_proof = prev.map(|(f, t)| create_recursive_proof(f, t));

        let merkle_proof = create_state(from, step_v.to_vk()).generate_next_vk_proof();

        MohoRecursiveInput {
            moho_verifier: moho_v,
            prev_recursive_proof: prev_proof,
            incremental_step_proof: step_proof,
            step_proof_verifier: step_v,
            step_vk_merkle_proof: merkle_proof,
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
        // Test with wrong verifier - should fail Merkle proof check
        let mut inp = create_input(2, 3, None);
        inp.step_proof_verifier = MockVerifier::new("ASM 2".to_string());

        let result = verify_and_chain_transition(inp.clone());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MohoError::InvalidMerkleProof));

        // Test with correct verifier - should succeed
        inp.step_proof_verifier = MockVerifier::new("ASM".to_string());
        let expected = create_step_proof(2, 3);
        let result = verify_and_chain_transition(inp).unwrap();
        assert_eq!(&result, expected.transition());
    }

    #[test]
    fn test_verify_and_chain_transition_invalid_incremental_proof() {
        // Test with invalid step proof - should fail verification
        let mut inp = create_input(1, 2, None);
        let (t, _) = inp.incremental_step_proof.into_parts();
        inp.incremental_step_proof = MohoTransitionWithProof::new(t, Proof::default());

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
        let mut inp = create_input(2, 3, Some((1, 2)));
        let (t, _) = inp.prev_recursive_proof.unwrap().into_parts();
        inp.prev_recursive_proof = Some(MohoTransitionWithProof::new(t, Proof::default()));

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
