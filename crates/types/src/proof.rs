//! Proof related types.

use borsh::{BorshDeserialize, BorshSerialize};

/// Verification key for the inner state transition.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct InnerVerificationKey(Vec<u8>);

/// Generic proof.
#[derive(Clone, Debug)]
#[expect(unused)]
pub struct Proof<'p>(&'p [u8]);

/// Generic public parameters.
// TODO how should this actually work?
#[derive(Clone, Debug)]
#[expect(unused)]
pub struct PublicParams<'i>(&'i [u8]);

/// Abstraction over inner proof proving system.
pub trait ProofSystem {
    /// Sanity checks a verification key.
    ///
    /// If this returns false, the proof is invalid.
    fn check_vk(vk: &InnerVerificationKey) -> bool;

    /// Verifies a proof against a verification key.
    ///
    /// If this returns false, the proof is invalid.
    fn verify_proof<'p>(
        vk: &InnerVerificationKey,
        proof: &Proof<'p>,
        public_params: &PublicParams<'p>,
    ) -> bool;
}
