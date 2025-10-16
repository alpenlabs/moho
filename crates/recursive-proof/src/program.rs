use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

use borsh::{BorshDeserialize, BorshSerialize};
use moho_types::{MerkleProof, MohoAttestation};
use strata_predicate::PredicateKey;
use zkaleido::{ZkVmError, ZkVmProgram, ZkVmProgramPerf, ZkVmResult};
use zkaleido_native_adapter::{NativeHost, NativeMachine};

use crate::{process_recursive_moho_proof, transition::MohoTransitionWithProof};

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
    pub(crate) moho_verifier: PredicateKey,
    /// Previous recursive moho proof
    pub(crate) prev_recursive_proof: Option<MohoTransitionWithProof>,
    /// Incremental step proof
    pub(crate) incremental_step_proof: MohoTransitionWithProof,
    /// Verifying Key to verify the incremenal step proof from initial_state to final_state
    pub(crate) step_proof_verifier: PredicateKey,
    /// Merkle proof of `step_proof_verifier` within initial_state
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

impl MohoRecursiveProgram {
    /// Returns the native host for the moho recursive program
    pub fn native_host() -> NativeHost {
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                catch_unwind(AssertUnwindSafe(|| {
                    process_recursive_moho_proof(zkvm);
                }))
                .map_err(|_| ZkVmError::ExecutionError(Self::name()))?;
                Ok(())
            })),
        }
    }

    /// Executes the moho recursive program in the native mode
    pub fn execute(
        input: &<Self as ZkVmProgram>::Input,
    ) -> ZkVmResult<<Self as ZkVmProgram>::Output> {
        // Get the native host and delegate to the trait's execute method
        let host = Self::native_host();
        <Self as ZkVmProgram>::execute(input, &host)
    }
}
