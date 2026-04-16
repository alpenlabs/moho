use zkaleido::{ZkVmProgram, ZkVmResult};
use zkaleido_native_adapter::NativeHost;

use crate::{MohoRecursiveInput, MohoRecursiveOutput, process_recursive_moho_proof};

/// A host-agnostic ZkVM “program” that encapsulates the recursive proof logic
/// for the Moho protocol.
#[derive(Debug)]
pub struct MohoRecursiveProgram;

impl ZkVmProgram for MohoRecursiveProgram {
    type Input = MohoRecursiveInput;
    type Output = MohoRecursiveOutput;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn test_execute_base_case() {
        let moho = SchnorrPredicate::new_random();
        let step = SchnorrPredicate::new_random();

        let input = create_input(1, 2, None, &moho, &step);
        let output = MohoRecursiveProgram::execute(&input).unwrap();

        let expected = expected_attestation(1, 2, &step.predicate);
        assert_eq!(*output.attestation().genesis(), *expected.from());
        assert_eq!(*output.attestation().proven(), *expected.to());
    }

    #[test]
    fn test_execute_chained() {
        let moho = SchnorrPredicate::new_random();
        let step = SchnorrPredicate::new_random();

        let input = create_input(2, 3, Some((1, 2)), &moho, &step);
        let output = MohoRecursiveProgram::execute(&input).unwrap();

        let first = expected_attestation(1, 2, &step.predicate);
        let second = expected_attestation(2, 3, &step.predicate);
        assert_eq!(*output.attestation().genesis(), *first.from());
        assert_eq!(*output.attestation().proven(), *second.to());
    }
}
