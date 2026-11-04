use moho_types::{
    RecursiveMohoAttestation, RecursiveMohoProof, StepMohoAttestation, StepMohoProof,
};
use ssz::ssz_encode;
use strata_merkle::Sha256NoPrefixHasher;
use strata_predicate::PredicateKey;
use tree_hash::{Sha256Hasher, TreeHash};
use zkaleido::{ZkVmEnv, ZkVmEnvSsz};

use crate::{
    MohoError, MohoRecursiveInput, MohoRecursiveOutput,
    errors::{InvalidRecursiveProofError, InvalidStepProofError},
};

/// Leaf index of `next_predicate` in the [`MohoState`](moho_types::MohoState) tree.
///
/// The tree hash of `MohoState` merkleizes its three fields (`inner_state`, `next_predicate`,
/// `export_state`) padded to four leaves, so `next_predicate` is leaf 1 at depth 2.
const NEXT_PREDICATE_LEAF_INDEX: u64 = 1;

/// Depth of the [`MohoState`](moho_types::MohoState) field tree.
const MOHO_STATE_TREE_DEPTH: usize = 2;

/// Reads an SSZ-encoded [`MohoRecursiveInput`] from the zkVM, verifies and chains the proof,
/// and commits the resulting [`MohoRecursiveOutput`] back to the zkVM.
///
/// # Panics
///
/// Panics if decoding the input or verifying/chaining the proof fails.
pub fn process_recursive_moho_proof(zkvm: &impl ZkVmEnv) {
    let input: MohoRecursiveInput = zkvm.read_ssz();

    let moho_predicate = input.moho_predicate.clone();
    let attestation = verify_and_chain(input).expect("failed to verify and chain moho proof");
    let output = MohoRecursiveOutput::new(attestation, moho_predicate);

    zkvm.commit_ssz(&output);
}

/// Verifies the step and recursive proofs, then chains them into a single
/// [`RecursiveMohoAttestation`].
///
/// 1. Verifies that the step predicate key is the `next_predicate` field of the starting state's
///    Merkle commitment.
/// 2. Verifies the step proof against the step predicate.
/// 3. If a previous recursive proof exists, verifies it and chains both attestations — checking
///    that the recursive proof's proven state matches the step proof's starting state.
pub fn verify_and_chain(input: MohoRecursiveInput) -> Result<RecursiveMohoAttestation, MohoError> {
    // 1: Ensure the step proof's predicate key is the starting state's `next_predicate`.
    //
    // The Merkle check binds the proof to the index it claims and to the tree depth, but a
    // valid proof for another field of the state would pass it too. So we pin the index.
    let merkle_proof = &input.step_predicate_merkle_proof;
    if merkle_proof.index() != NEXT_PREDICATE_LEAF_INDEX {
        return Err(MohoError::WrongPredicateLeaf {
            index: merkle_proof.index(),
        });
    }

    let next_predicate_hash =
        <_ as TreeHash>::tree_hash_root::<Sha256Hasher>(&input.step_predicate).into_inner();
    let expected_root = input
        .incremental_step_proof
        .attestation()
        .from()
        .commitment();
    if !merkle_proof.verify_with_root_at_depth::<Sha256NoPrefixHasher>(
        expected_root.inner(),
        MOHO_STATE_TREE_DEPTH,
        &next_predicate_hash,
    ) {
        return Err(MohoError::InvalidMerkleProof);
    }

    // 2: Verify the step proof.
    let step_att = verify_step_proof(input.incremental_step_proof, &input.step_predicate)
        .map_err(MohoError::InvalidIncrementalProof)?;

    // 3: Handle previous recursive proof and continuity check.
    match input.prev_recursive_proof {
        // No previous proof: the step becomes the initial recursive attestation.
        None => {
            let (from, to) = step_att.into_parts();
            Ok(RecursiveMohoAttestation::new(from, to))
        }

        // Previous proof exists: verify it, then chain.
        Some(prev_proof) => {
            let prev_att = verify_recursive_proof(prev_proof, &input.moho_predicate)
                .map_err(MohoError::InvalidRecursiveProof)?;

            prev_att.chain(step_att).map_err(MohoError::from)
        }
    }
}

/// Verifies a [`StepMohoProof`] against a predicate key.
///
/// Step proofs attest directly to the SSZ-encoded [`StepMohoAttestation`].
/// On success, returns the attestation by consuming the proof.
fn verify_step_proof(
    proof: StepMohoProof,
    verifier: &PredicateKey,
) -> Result<StepMohoAttestation, Box<InvalidStepProofError>> {
    let claim = ssz_encode(proof.attestation());
    match verifier.verify_claim_witness(&claim, proof.proof()) {
        Ok(()) => Ok(proof.into_attestation()),
        Err(e) => Err(Box::new(InvalidStepProofError {
            attestation: proof.into_attestation(),
            source: e,
        })),
    }
}

/// Verifies a [`RecursiveMohoProof`] against a predicate key.
///
/// Recursive proofs attest to a [`MohoRecursiveOutput`] which wraps the attestation together
/// with the predicate key as an additional public value.
/// On success, returns the attestation by consuming the proof.
fn verify_recursive_proof(
    proof: RecursiveMohoProof,
    verifier: &PredicateKey,
) -> Result<RecursiveMohoAttestation, Box<InvalidRecursiveProofError>> {
    let (attestation, proof) = proof.into_parts();
    let output = MohoRecursiveOutput::new(attestation.clone(), verifier.clone());
    let claim = ssz_encode(&output);
    match verifier.verify_claim_witness(&claim, &proof) {
        Ok(()) => Ok(attestation),
        Err(e) => Err(Box::new(InvalidRecursiveProofError {
            attestation,
            source: e,
        })),
    }
}

#[cfg(test)]
mod tests {
    use moho_types::{ExportState, InnerStateCommitment, MohoState};
    use strata_merkle::MerkleProofB32;

    use super::*;
    use crate::test_utils::*;

    #[test]
    fn test_verify_and_chain_success() {
        let moho = SchnorrPredicate::new_random();
        let step = SchnorrPredicate::new_random();

        let expected = expected_attestation(1, 2, &step.predicate);
        let result = verify_and_chain(create_input(1, 2, None, &moho, &step)).unwrap();
        assert_eq!(*result.genesis(), *expected.from());
        assert_eq!(*result.proven(), *expected.to());

        let expected = expected_attestation(10, 20, &step.predicate);
        let result = verify_and_chain(create_input(10, 20, None, &moho, &step)).unwrap();
        assert_eq!(*result.genesis(), *expected.from());
        assert_eq!(*result.proven(), *expected.to());
    }

    #[test]
    fn test_verify_and_chain_with_previous_proof_success() {
        let moho = SchnorrPredicate::new_random();
        let step = SchnorrPredicate::new_random();

        let from_att = expected_attestation(1, 2, &step.predicate);
        let to_att = expected_attestation(2, 3, &step.predicate);
        let result = verify_and_chain(create_input(2, 3, Some((1, 2)), &moho, &step)).unwrap();
        assert_eq!(*result.genesis(), *from_att.from());
        assert_eq!(*result.proven(), *to_att.to());

        let from_att = expected_attestation(1, 3, &step.predicate);
        let to_att = expected_attestation(3, 10, &step.predicate);
        let result = verify_and_chain(create_input(3, 10, Some((1, 3)), &moho, &step)).unwrap();
        assert_eq!(*result.genesis(), *from_att.from());
        assert_eq!(*result.proven(), *to_att.to());
    }

    #[test]
    fn test_verify_and_chain_invalid_chain() {
        let moho = SchnorrPredicate::new_random();
        let step = SchnorrPredicate::new_random();
        let result = verify_and_chain(create_input(3, 5, Some((1, 2)), &moho, &step));
        assert!(matches!(result, Err(MohoError::InvalidMohoChain(_))));
    }

    #[test]
    fn test_verify_and_chain_invalid_merkle_proof() {
        let moho = SchnorrPredicate::new_random();
        let step = SchnorrPredicate::new_random();
        let mut input = create_input(2, 3, None, &moho, &step);
        input.step_predicate = SchnorrPredicate::new_random().predicate;

        let result = verify_and_chain(input);
        assert!(matches!(result, Err(MohoError::InvalidMerkleProof)));

        let expected = expected_attestation(2, 3, &step.predicate);
        let corrected = create_input(2, 3, None, &moho, &step);
        let result = verify_and_chain(corrected).unwrap();
        assert_eq!(*result.genesis(), *expected.from());
        assert_eq!(*result.proven(), *expected.to());
    }

    /// Builds an input whose step is signed by `attacker` and whose starting state commits
    /// to `attacker`'s key in `inner_state`, while `next_predicate` stays `honest`.
    fn input_with_predicate_in_inner_state(
        moho: &SchnorrPredicate,
        honest: &SchnorrPredicate,
        attacker: &SchnorrPredicate,
    ) -> (MohoRecursiveInput, MohoState) {
        let attacker_root =
            <_ as TreeHash>::tree_hash_root::<Sha256Hasher>(&attacker.predicate).into_inner();
        let from_state = MohoState::new(
            InnerStateCommitment::from(attacker_root),
            honest.predicate.clone(),
            ExportState::new(vec![]).unwrap(),
        );
        let to_state = create_state(2, attacker.predicate.clone());
        let (step_proof, _) =
            step_proof_with_merkle(1, 2, &from_state, &to_state, &attacker.signing_key);

        let input = MohoRecursiveInput {
            moho_predicate: moho.predicate.clone(),
            prev_recursive_proof: None,
            incremental_step_proof: step_proof,
            step_predicate: attacker.predicate.clone(),
            step_predicate_merkle_proof: create_state_field_proof(&from_state, 0),
        };
        (input, from_state)
    }

    #[test]
    fn test_verify_and_chain_rejects_predicate_at_other_leaf() {
        let moho = SchnorrPredicate::new_random();
        let honest = SchnorrPredicate::new_random();
        let attacker = SchnorrPredicate::new_random();
        let (input, from_state) = input_with_predicate_in_inner_state(&moho, &honest, &attacker);

        // The leaf-0 proof does reach the starting state's root.
        let attacker_root =
            <_ as TreeHash>::tree_hash_root::<Sha256Hasher>(&attacker.predicate).into_inner();
        assert!(
            input
                .step_predicate_merkle_proof
                .verify_with_root::<Sha256NoPrefixHasher>(
                    from_state.compute_commitment().inner(),
                    &attacker_root,
                )
        );

        let result = verify_and_chain(input);
        assert!(matches!(
            result,
            Err(MohoError::WrongPredicateLeaf { index: 0 })
        ));
    }

    #[test]
    fn test_verify_and_chain_rejects_wrong_depth() {
        let moho = SchnorrPredicate::new_random();
        let step = SchnorrPredicate::new_random();

        for depth in [0, 1, 3] {
            let mut input = create_input(1, 2, None, &moho, &step);
            let mut cohashes = input.step_predicate_merkle_proof.cohashes();
            cohashes.resize(depth, [0u8; 32]);
            input.step_predicate_merkle_proof = MerkleProofB32::from_cohashes(cohashes, 1);

            let result = verify_and_chain(input);
            assert!(
                matches!(result, Err(MohoError::InvalidMerkleProof)),
                "depth {depth} should be rejected"
            );
        }
    }

    #[test]
    fn test_verify_and_chain_invalid_incremental_proof() {
        let moho = SchnorrPredicate::new_random();
        let step = SchnorrPredicate::new_random();
        let bad_step_key = SchnorrPredicate::new_random();

        let from_state = create_state(1, step.predicate.clone());
        let to_state = create_state(2, step.predicate.clone());
        let att = step_attestation(1, 2, &from_state, &to_state);
        let mut bad_signature = sign_attestation(&att, &bad_step_key.signing_key);
        bad_signature[0] ^= 0xFF;
        let step_proof = StepMohoProof::new(att, bad_signature);

        // Sanity check: the step proof should not verify under the expected predicate
        assert!(
            verify_step_proof(step_proof.clone(), &step.predicate).is_err(),
            "corrupted step proof should fail standalone verification"
        );

        let input = MohoRecursiveInput {
            moho_predicate: moho.predicate.clone(),
            prev_recursive_proof: None,
            incremental_step_proof: step_proof,
            step_predicate: step.predicate.clone(),
            step_predicate_merkle_proof: create_predicate_inclusion_proof(&from_state),
        };

        let result = verify_and_chain(input);
        assert!(matches!(result, Err(MohoError::InvalidIncrementalProof(_))));
    }

    #[test]
    fn test_verify_and_chain_invalid_recursive_proof() {
        let moho = SchnorrPredicate::new_random();
        let step = SchnorrPredicate::new_random();
        let mut input = create_input(2, 3, Some((1, 2)), &moho, &step);
        input.moho_predicate = SchnorrPredicate::new_random().predicate;

        let result = verify_and_chain(input);
        assert!(matches!(result, Err(MohoError::InvalidRecursiveProof(_))));
    }

    #[test]
    fn test_verify_and_chain_edge_case_same_state() {
        let moho = SchnorrPredicate::new_random();
        let step = SchnorrPredicate::new_random();
        let input = create_input(5, 5, None, &moho, &step);
        assert!(verify_and_chain(input).is_ok());
    }
}
