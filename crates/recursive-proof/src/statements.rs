use moho_types::{RecursiveMohoAttestation, RecursiveMohoProof, StepMohoProof};
use ssz::{Decode, Encode, ssz_encode};
use strata_merkle::Sha256NoPrefixHasher;
use strata_predicate::PredicateKey;
use tree_hash::{Sha256Hasher, TreeHash};
use zkaleido::ZkVmEnv;

use crate::{
    MohoError, MohoRecursiveInput, MohoRecursiveOutput,
    errors::{InvalidRecursiveProofError, InvalidStepProofError},
};

/// Reads an SSZ-encoded [`MohoRecursiveInput`] from the zkVM, verifies and chains the proof,
/// and commits the resulting [`MohoRecursiveOutput`] back to the zkVM.
///
/// # Panics
///
/// Panics if decoding the input or verifying/chaining the proof fails.
pub fn process_recursive_moho_proof(zkvm: &impl ZkVmEnv) {
    let input_ssz_bytes = zkvm.read_buf();
    let input = MohoRecursiveInput::from_ssz_bytes(&input_ssz_bytes).unwrap();
    let moho_predicate = input.moho_predicate.clone();

    let attestation = verify_and_chain(input).unwrap();

    let output = MohoRecursiveOutput::new(attestation, moho_predicate);
    let output_bytes = output.as_ssz_bytes();
    zkvm.commit_buf(&output_bytes);
}

/// Verifies the step and recursive proofs, then chains them into a single
/// [`RecursiveMohoAttestation`].
///
/// 1. Verifies that the step predicate key is included in the starting state's Merkle commitment.
/// 2. Verifies the step proof against the step predicate.
/// 3. If a previous recursive proof exists, verifies it and chains both attestations — checking
///    that the recursive proof's proven state matches the step proof's starting state.
pub fn verify_and_chain(input: MohoRecursiveInput) -> Result<RecursiveMohoAttestation, MohoError> {
    // 1: Ensure the step proof's predicate key is part of the starting state's Merkle root.
    let next_predicate_hash =
        <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&input.step_predicate).into_inner();
    let expected_root = input
        .incremental_step_proof
        .attestation()
        .from()
        .commitment();
    if !input
        .step_predicate_merkle_proof
        .verify_with_root::<Sha256NoPrefixHasher>(expected_root.inner(), &next_predicate_hash)
    {
        return Err(MohoError::InvalidMerkleProof);
    }

    // 2: Verify the step proof.
    verify_step_proof(&input.incremental_step_proof, &input.step_predicate)
        .map_err(MohoError::InvalidIncrementalProof)?;

    let step_att = input.incremental_step_proof.attestation().clone();

    // 3: Handle previous recursive proof and continuity check.
    match input.prev_recursive_proof {
        // No previous proof: the step becomes the initial recursive attestation.
        None => Ok(RecursiveMohoAttestation::new(
            step_att.from().clone(),
            step_att.to().clone(),
        )),

        // Previous proof exists: verify it, then chain.
        Some(prev_proof) => {
            verify_recursive_proof(&prev_proof, &input.moho_predicate)
                .map_err(MohoError::InvalidRecursiveProof)?;

            let prev_att = prev_proof.attestation().clone();
            let prev_proven = prev_att.proven().clone();
            let step_from = step_att.from().clone();

            prev_att.chain(step_att).ok_or_else(|| {
                MohoError::InvalidMohoChain {
                    recursive_end: prev_proven,
                    step_start: step_from,
                }
            })
        }
    }
}

/// Verifies a [`StepMohoProof`] against a predicate key.
///
/// Step proofs attest directly to the SSZ-encoded [`StepMohoAttestation`].
fn verify_step_proof(
    proof: &StepMohoProof,
    verifier: &PredicateKey,
) -> Result<(), InvalidStepProofError> {
    let claim = ssz_encode(proof.attestation());
    verifier
        .verify_claim_witness(&claim, proof.proof())
        .map_err(|e| InvalidStepProofError {
            attestation: proof.attestation().clone(),
            source: e,
        })
}

/// Verifies a [`RecursiveMohoProof`] against a predicate key.
///
/// Recursive proofs attest to a [`MohoRecursiveOutput`] which wraps the attestation together
/// with the predicate key as an additional public value.
fn verify_recursive_proof(
    proof: &RecursiveMohoProof,
    verifier: &PredicateKey,
) -> Result<(), InvalidRecursiveProofError> {
    let output = MohoRecursiveOutput::new(proof.attestation().clone(), verifier.clone());
    let claim = ssz_encode(&output);
    verifier
        .verify_claim_witness(&claim, proof.proof())
        .map_err(|e| InvalidRecursiveProofError {
            attestation: proof.attestation().clone(),
            source: e,
        })
}

#[cfg(test)]
mod tests {
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
        assert!(matches!(result, Err(MohoError::InvalidMohoChain { .. })));
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
            verify_step_proof(&step_proof, &step.predicate).is_err(),
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
