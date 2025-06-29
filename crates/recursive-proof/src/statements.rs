use moho_types::{MerkleTree, MohoState};
use zkaleido::ZkVmEnv;

use crate::program::MohoRecursiveInput;

pub fn process_recursive_moho_proof(zkvm: &impl ZkVmEnv) {
    // 0. Read the input
    let input: MohoRecursiveInput = zkvm.read_borsh();

    // 1. Verify that the incremental proof vk is part of the moho state
    let next_vk_hash = MerkleTree::hash_serializable(&input.step_proof_vk);
    assert!(MohoState::verify_proof_against_commitment(
        input
            .incremental_step_proof
            .transition()
            .from()
            .commitment(),
        &input.step_vk_merkle_proof,
        &next_vk_hash,
    ));

    // 2. Verify the incremental proof
    input
        .incremental_step_proof
        .verify(input.step_proof_vk)
        .unwrap();

    // 3. Verify the recursive proof if any to construct the full transition
    let full_transition = match &input.prev_recursive_proof {
        Some(prev_proof) => {
            prev_proof.verify(input.moho_vk).unwrap();
            prev_proof
                .transition()
                .clone()
                .chain(input.incremental_step_proof.transition().clone())
                .unwrap()
        }
        None => input.incremental_step_proof.transition().clone(),
    };

    zkvm.commit_borsh(&full_transition);
}
