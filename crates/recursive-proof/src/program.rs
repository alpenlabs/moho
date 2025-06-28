use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

use borsh::{BorshDeserialize, BorshSerialize};
use moho_types::{MohoAttestation, MohoStateCommitment, StateRefAttestation, StateReference};
use zkaleido::{Proof, VerifyingKey, ZkVm, ZkVmProgram, ZkVmProgramPerf};
use zkaleido_native_adapter::{NativeHost, NativeMachine};

#[derive(Debug)]
pub struct MohoRecursiveProgram;

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct MohoRecursiveInput {
    /// Moho proof’s own vk, necessary to verify the previous proof
    pub(crate) moho_vk: VerifyingKey,
    /// Previous recursive moho proof
    pub(crate) prev_proof: Option<Proof>,
    /// Incremental moho proof
    pub(crate) step_proof: Proof,
    /// Initial state
    pub(crate) initial_state: StateRefAttestation,
    /// Final state
    pub(crate) final_state: StateRefAttestation,
    /// Merkle proof of next_vk within initial_state
    pub(crate) next_vk_proof: Proof,
}

impl ZkVmProgram for MohoRecursiveProgram {
    type Input = MohoRecursiveInput;
    type Output = MohoAttestation;

    fn name() -> String {
        "Moho Recursive".to_string()
    }

    fn proof_type() -> zkaleido::ProofType {
        zkaleido::ProofType::Groth16
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> zkaleido::ZkVmInputResult<B::Input>
    where
        B: zkaleido::ZkVmInputBuilder<'a>,
    {
        let mut zkvm_input = B::new();
        zkvm_input.write_borsh(&input)?;
        zkvm_input.build()
    }

    fn process_output<H>(
        public_values: &zkaleido::PublicValues,
    ) -> zkaleido::ZkVmResult<Self::Output>
    where
        H: zkaleido::ZkVmHost,
    {
        H::extract_borsh_public_output(public_values)
    }
}

impl ZkVmProgramPerf for MohoRecursiveProgram {}
