use ssz::{Decode, Encode};
use strata_merkle::MerkleProofB32;
use tree_hash::{Sha256Hasher, TreeHash};
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
    let input_ssz_bytes = zkvm.read_buf();
    let input = MohoRecursiveInput::from_ssz_bytes(&input_ssz_bytes).unwrap();
    let moho_predicate = input.moho_predicate.clone();
    let full_transition = verify_and_chain_transition(input).unwrap();
    let output = MohoRecursiveOutput {
        moho_predicate,
        transition: full_transition,
    };
    let output_bytes = output.as_ssz_bytes();
    zkvm.commit_buf(&output_bytes);
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
    fn compute_root_no_prefix(proof: &MerkleProofB32, leaf: &[u8; 32]) -> [u8; 32] {
        use k256::sha2::{Digest, Sha256};

        let mut cur = *leaf;
        let mut flags = proof.index();
        for co in proof.cohashes() {
            let mut hasher = Sha256::new();
            if flags & 1 == 1 {
                hasher.update(co);
                hasher.update(cur);
            } else {
                hasher.update(cur);
                hasher.update(co);
            }
            cur = hasher.finalize().into();
            flags >>= 1;
        }
        cur
    }

    // 1: Ensure the incremental proof predicate key is part of the Moho state Merkle root.
    let next_predicate_hash =
        <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&input.step_predicate).into_inner();
    let expected_root = input
        .incremental_step_proof
        .transition()
        .from()
        .commitment();
    let computed_root =
        compute_root_no_prefix(&input.step_predicate_merkle_proof, &next_predicate_hash);
    if computed_root != expected_root.0 {
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
    use k256::{
        schnorr::{SigningKey, signature::Signer},
        sha2::{Digest, Sha256},
    };
    use moho_types::{MohoState, StateRefAttestation, StateReference};
    use rand_core::OsRng;
    use strata_merkle::{BinaryMerkleTree, MerkleProofB32, Sha256NoPrefixHasher};
    use strata_predicate::{PredicateKey, PredicateTypeId};
    use ssz::ssz_encode;
    use tree_hash::{Sha256Hasher as TreeSha256Hasher, TreeHash};

    use super::*;
    use crate::transition::{MohoTransitionWithProof, Transition};

    #[derive(Clone)]
    struct PredicateWithKey {
        signing_key: SigningKey,
        predicate: PredicateKey,
    }

    impl PredicateWithKey {
        fn new_schnorr() -> Self {
            let signing_key = SigningKey::random(&mut OsRng);
            let predicate = PredicateKey::new(
                PredicateTypeId::Bip340Schnorr,
                signing_key.verifying_key().to_bytes().to_vec(),
            );
            Self {
                signing_key,
                predicate,
            }
        }
    }

    fn predicate_hash(predicate: &PredicateKey) -> [u8; 32] {
        <_ as TreeHash<TreeSha256Hasher>>::tree_hash_root(predicate).into_inner()
    }

    fn create_state(id: u8, predicate: &PredicateKey) -> MohoState {
        let inner_state = moho_types::InnerStateCommitment::from([id; 32]);
        let export_state = moho_types::ExportState::new(vec![]);
        MohoState::new(inner_state, predicate.clone(), export_state)
    }

    fn attestation(id: u8, state: &MohoState) -> StateRefAttestation {
        let commitment = state.compute_commitment();
        let reference = StateReference::from([id; 32]);
        StateRefAttestation::new(reference, commitment)
    }

    fn create_predicate_inclusion_proof(state: &MohoState) -> MerkleProofB32 {
        let leaves = vec![
            <_ as TreeHash<TreeSha256Hasher>>::tree_hash_root(&state.inner_state).into_inner(),
            <_ as TreeHash<TreeSha256Hasher>>::tree_hash_root(&state.next_predicate).into_inner(),
            <_ as TreeHash<TreeSha256Hasher>>::tree_hash_root(&state.export_state).into_inner(),
            [0u8; 32],
        ];

        let generic_proof = BinaryMerkleTree::from_leaves::<Sha256NoPrefixHasher>(leaves)
            .expect("valid tree")
            .gen_proof(1)
            .expect("proof exists");
        let proof = MerkleProofB32::from_generic(&generic_proof);

        let predicate_leaf = predicate_hash(&state.next_predicate);
        let commitment = state.compute_commitment();
        let mut computed = predicate_leaf;
        let mut flags = proof.index();
        for co in proof.cohashes() {
            let mut hasher = Sha256::new();
            if flags & 1 == 1 {
                hasher.update(co);
                hasher.update(computed);
            } else {
                hasher.update(computed);
                hasher.update(co);
            }
            computed = hasher.finalize().into();
            flags >>= 1;
        }
        assert_eq!(
            computed, commitment.0,
            "merkle proof should validate against the state commitment"
        );

        proof
    }

    fn transition_with_predicate(
        from: u8,
        to: u8,
        from_state: &MohoState,
        to_state: &MohoState,
    ) -> MohoStateTransition {
        Transition::new(
            attestation(from, from_state),
            attestation(to, to_state),
        )
    }

    fn sign_transition(transition: &MohoStateTransition, signing_key: &SigningKey) -> Vec<u8> {
        signing_key
            .sign(&ssz_encode(transition))
            .to_bytes()
            .to_vec()
    }

    fn transition_with_proof(
        from: u8,
        to: u8,
        from_state: &MohoState,
        to_state: &MohoState,
        signing_key: &SigningKey,
    ) -> (MohoTransitionWithProof, MerkleProofB32) {
        let transition = transition_with_predicate(from, to, from_state, to_state);
        let signature = sign_transition(&transition, signing_key);
        let proof = MohoTransitionWithProof::new(transition, signature);
        let merkle_proof = create_predicate_inclusion_proof(from_state);
        (proof, merkle_proof)
    }

    fn create_input(
        from: u8,
        to: u8,
        prev: Option<(u8, u8)>,
        moho: &PredicateWithKey,
        step: &PredicateWithKey,
    ) -> MohoRecursiveInput {
        let from_state = create_state(from, &step.predicate);
        let to_state = create_state(to, &step.predicate);
        let (step_proof, step_predicate_merkle_proof) =
            transition_with_proof(from, to, &from_state, &to_state, &step.signing_key);

        let prev_recursive_proof = prev.map(|(f, t)| {
            let prev_from_state = create_state(f, &step.predicate);
            let prev_to_state = create_state(t, &step.predicate);
            let transition = transition_with_predicate(f, t, &prev_from_state, &prev_to_state);
            let signature = sign_transition(&transition, &moho.signing_key);
            MohoTransitionWithProof::new(transition, signature)
        });

        MohoRecursiveInput {
            moho_predicate: moho.predicate.clone(),
            prev_recursive_proof,
            incremental_step_proof: step_proof,
            step_predicate: step.predicate.clone(),
            step_predicate_merkle_proof,
        }
    }

    fn expected_transition(from: u8, to: u8, predicate: &PredicateKey) -> MohoStateTransition {
        let from_state = create_state(from, predicate);
        let to_state = create_state(to, predicate);
        transition_with_predicate(from, to, &from_state, &to_state)
    }

    #[test]
    fn test_verify_and_chain_transition_success() {
        let moho = PredicateWithKey::new_schnorr();
        let step = PredicateWithKey::new_schnorr();

        let expected = expected_transition(1, 2, &step.predicate);
        let result = verify_and_chain_transition(create_input(1, 2, None, &moho, &step)).unwrap();
        assert_eq!(result, expected);

        let expected = expected_transition(10, 20, &step.predicate);
        let result =
            verify_and_chain_transition(create_input(10, 20, None, &moho, &step)).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_verify_and_chain_transition_with_previous_proof_success() {
        let moho = PredicateWithKey::new_schnorr();
        let step = PredicateWithKey::new_schnorr();

        let expected = expected_transition(1, 3, &step.predicate);
        let result =
            verify_and_chain_transition(create_input(2, 3, Some((1, 2)), &moho, &step)).unwrap();
        assert_eq!(result, expected);

        let expected = expected_transition(1, 10, &step.predicate);
        let result =
            verify_and_chain_transition(create_input(3, 10, Some((1, 3)), &moho, &step)).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_verify_and_chain_transition_invalid_chain() {
        let moho = PredicateWithKey::new_schnorr();
        let step = PredicateWithKey::new_schnorr();
        let result = verify_and_chain_transition(create_input(3, 5, Some((1, 2)), &moho, &step));
        assert!(matches!(result, Err(MohoError::InvalidMohoChain(_))));
    }

    #[test]
    fn test_verify_and_chain_transition_invalid_merkle_proof() {
        let moho = PredicateWithKey::new_schnorr();
        let step = PredicateWithKey::new_schnorr();
        let mut input = create_input(2, 3, None, &moho, &step);
        input.step_predicate = PredicateWithKey::new_schnorr().predicate;

        let result = verify_and_chain_transition(input.clone());
        assert!(matches!(result, Err(MohoError::InvalidMerkleProof)));

        let expected = expected_transition(2, 3, &step.predicate);
        let corrected = create_input(2, 3, None, &moho, &step);
        let result = verify_and_chain_transition(corrected).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_verify_and_chain_transition_invalid_incremental_proof() {
        let moho = PredicateWithKey::new_schnorr();
        let step = PredicateWithKey::new_schnorr();
        let bad_step_key = PredicateWithKey::new_schnorr();

        let from_state = create_state(1, &step.predicate);
        let to_state = create_state(2, &step.predicate);
        let transition = transition_with_predicate(1, 2, &from_state, &to_state);
        let mut bad_signature = sign_transition(&transition, &bad_step_key.signing_key);
        bad_signature[0] ^= 0xFF; // ensure signature mismatch
        let incremental_step_proof = MohoTransitionWithProof::new(transition, bad_signature);

        // Sanity check: the step proof should not verify under the expected predicate
        assert!(
            incremental_step_proof.verify(&step.predicate).is_err(),
            "corrupted step proof should fail standalone verification"
        );

        let input = MohoRecursiveInput {
            moho_predicate: moho.predicate.clone(),
            prev_recursive_proof: None,
            incremental_step_proof,
            step_predicate: step.predicate.clone(),
            step_predicate_merkle_proof: create_predicate_inclusion_proof(&from_state),
        };

        let result = verify_and_chain_transition(input);
        assert!(matches!(
            result,
            Err(MohoError::InvalidIncrementalProof(_))
        ));
    }

    #[test]
    fn test_verify_and_chain_transition_invalid_recursive_proof() {
        let moho = PredicateWithKey::new_schnorr();
        let step = PredicateWithKey::new_schnorr();
        let mut input = create_input(2, 3, Some((1, 2)), &moho, &step);
        input.moho_predicate = PredicateWithKey::new_schnorr().predicate;

        let result = verify_and_chain_transition(input);
        assert!(matches!(
            result,
            Err(MohoError::InvalidRecursiveProof(_))
        ));
    }

    #[test]
    fn test_verify_and_chain_transition_edge_case_same_state() {
        let moho = PredicateWithKey::new_schnorr();
        let step = PredicateWithKey::new_schnorr();
        let input = create_input(5, 5, None, &moho, &step);
        assert!(verify_and_chain_transition(input).is_ok());
    }
}
