use moho_types::RecursiveMohoAttestation;
use zkaleido::{ZkVmProgram, ZkVmResult};
use zkaleido_native_adapter::NativeHost;

use crate::{MohoRecursiveInput, process_recursive_moho_proof};

/// A host-agnostic ZkVM “program” that encapsulates the recursive proof logic
/// for the Moho protocol.
#[derive(Debug)]
pub struct MohoRecursiveProgram;

impl ZkVmProgram for MohoRecursiveProgram {
    type Input = MohoRecursiveInput;
    type Output = RecursiveMohoAttestation;

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
        B::new().write_ssz(&input)?.build()
    }

    fn process_output<H>(
        public_values: &zkaleido::PublicValues,
    ) -> zkaleido::ZkVmResult<Self::Output>
    where
        H: zkaleido::ZkVmHost,
    {
        H::extract_ssz_public_output(public_values)
    }
}

impl MohoRecursiveProgram {
    /// Returns the native host for the moho recursive program
    pub fn native_host() -> NativeHost {
        NativeHost::new(process_recursive_moho_proof)
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
