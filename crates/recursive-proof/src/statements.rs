use moho_types::{MerkleTree, MohoState};
use zkaleido::ZkVmEnv;

use crate::program::MohoRecursiveInput;

pub fn process_recursive_moho_proof(zkvm: &impl ZkVmEnv) {
    // 0. Read the input
    let input: MohoRecursiveInput = zkvm.read_borsh();

    // 1. Verify that the incremental proof vk is part of the moho state
    let next_vk_hash = MerkleTree::hash_serializable(&input.next_vk);
    assert!(MohoState::verify_proof_against_commitment(
        input.initial_state.commitment(),
        &input.next_vk_proof,
        &next_vk_hash,
    ));

    // 2. Verify that the incremental proof
    let raw_public_params = borsh::to_vec(&(&input.initial_state, &input.final_state)).unwrap();
}
