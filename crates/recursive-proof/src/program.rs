use borsh::{BorshDeserialize, BorshSerialize};
use moho_types::{MerkleProof, MohoAttestation};
use zkaleido::{VerifyingKey, ZkVmProgram, ZkVmProgramPerf};

use crate::transition::MohoTransitionWithProof;

/// A host-agnostic ZkVM “program” that encapsulates the recursive proof logic
/// for the Moho protocol.
#[derive(Debug)]
pub struct MohoRecursiveProgram;

/// Input data for generating a recursive Moho proof that combines incremental and recursive proofs.
///
/// `MohoRecursiveInput` contains all the necessary components to create a new recursive proof
/// by combining a previous recursive proof (if it exists) with a new incremental step proof.
/// This enables efficient proof composition where each new recursive proof can represent
/// an arbitrarily long chain of state transitions while maintaining constant verification time.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct MohoRecursiveInput {
    /// Moho proof’s own vk, necessary to verify the previous proof
    pub(crate) moho_vk: VerifyingKey,
    /// Previous recursive moho proof
    pub(crate) prev_recursive_proof: Option<MohoTransitionWithProof>,
    /// Incremental step proof
    pub(crate) incremental_step_proof: MohoTransitionWithProof,
    /// Verifying Key to verify the step proof from initial_state to final_state
    pub(crate) step_proof_vk: VerifyingKey,
    /// Merkle proof of next_vk within initial_state
    pub(crate) step_vk_merkle_proof: MerkleProof,
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
