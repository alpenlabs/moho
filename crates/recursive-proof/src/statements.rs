use zkaleido::ZkVmEnv;

use crate::program::MohoRecursiveInput;

pub fn process_recursive_moho_proof(zkvm: &impl ZkVmEnv) {
    // 0. Read the input
    let input: MohoRecursiveInput = zkvm.read_borsh();

    // 1. Verify that the incremental proof vk is part of the moho state
    
}
