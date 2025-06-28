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
    pub(crate) moho_vk: VerifyingKey,
    pub(crate) prev_proof: Option<Proof>,
    pub(crate) step_proof: Proof,
    pub(crate) initial_state: StateRefAttestation,
    pub(crate) final_state: StateRefAttestation,
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
