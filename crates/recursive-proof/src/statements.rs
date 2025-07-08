use borsh::{BorshDeserialize, BorshSerialize};
use moho_types::{MerkleTree, MohoState};
use zkaleido::{ZkVmEnv, ZkVmVerifier};

use crate::{MohoError, MohoStateTransition, program::MohoRecursiveInput};

/// Reads a recursive Moho proof from the zkVM, verifies it, and commits the resulting state
/// transition.
///
/// # Arguments
///
/// * `zkvm` - A reference to an implementation of the ZkVmEnv trait, providing the zkVM environment
///   for reading and committing Borsh-encoded data.
///
/// # Panics
///
/// This function will panic if `verify_and_chain_transition` returns an Err,
/// as it calls `unwrap` on the result. Errors are mapped to `MohoError` variants.
pub fn process_recursive_moho_proof<V: ZkVmVerifier + BorshSerialize + BorshDeserialize>(
    zkvm: &impl ZkVmEnv,
) {
    let input: MohoRecursiveInput<V> = zkvm.read_borsh();
    let full_transition = verify_and_chain_transition(input).unwrap();
    zkvm.commit_borsh(&full_transition);
}

/// Verifies and chains recursive Moho proof with inductive proof to produce a complete state
/// transition.
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
    let next_vk_hash = MerkleTree::hash_serializable(&input.step_proof_vk);
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
        .verify(&input.step_proof_vk)
        .map_err(MohoError::InvalidIncrementalProof)?;

    // Extract the incremental step transition and proof
    let (step_t, _step_proof) = input.incremental_step_proof.into_parts();

    // Step 3: If there is a previous recursive proof, verify and chain it.
    if let Some(prev_proof) = input.prev_recursive_proof {
        // Verify the previous recursive proof against the Moho VK
        prev_proof
            .verify(&input.moho_vk)
            .map_err(MohoError::InvalidRecursiveProof)?;

        // Extract the previous state transition
        let (prev_t, _proof) = prev_proof.into_parts();

        // Chain the previous transition with the new base transition, returning the combined
        // transition
        return prev_t
            .chain(step_t)
            .map_err(|e| MohoError::InvalidMohoChain(Box::new(e)));
    }

    // No previous proof: return the base transition directly
    Ok(step_t)
}
