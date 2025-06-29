//! Proof related types.

use zkaleido::{Proof, PublicValues, VerifyingKey};

/// Abstraction over inner proof proving system.
pub trait ProofSystem {
    /// Sanity checks a verification key.
    ///
    /// If this returns false, the proof is invalid.
    fn check_vk(vk: &VerifyingKey) -> bool;

    /// Verifies a proof against a verification key.
    ///
    /// If this returns false, the proof is invalid.
    fn verify_proof<'p>(vk: &VerifyingKey, proof: &Proof, public_params: &PublicValues) -> bool;
}

pub struct MockProofSystem {}

impl ProofSystem for MockProofSystem {
    fn check_vk(_vk: &VerifyingKey) -> bool {
        true
    }

    fn verify_proof<'p>(_vk: &VerifyingKey, _proof: &Proof, _public_params: &PublicValues) -> bool {
        true
    }
}
