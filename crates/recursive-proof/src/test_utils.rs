//! Test utilities for constructing Moho proofs, states, and transitions.
use k256::schnorr::{SigningKey, signature::Signer};
use moho_types::{
    MohoState, RecursiveMohoAttestation, RecursiveMohoProof, StateRefAttestation, StateReference,
    StepMohoAttestation, StepMohoProof,
};
use ssz::ssz_encode;
use strata_merkle::{BinaryMerkleTree, MerkleProofB32, Sha256NoPrefixHasher};
use strata_predicate::{PredicateKey, PredicateTypeId};
use tree_hash::{Sha256Hasher as TreeSha256Hasher, TreeHash};

use crate::{MohoRecursiveOutput, io::MohoRecursiveInput};

/// A Schnorr key pair bundled with a [`PredicateKey`] for convenient test setup.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct SchnorrPredicate {
    /// The signing key used to produce signatures.
    pub signing_key: SigningKey,
    /// The predicate key derived from the signing key.
    pub predicate: PredicateKey,
}

impl SchnorrPredicate {
    /// Creates a new random Schnorr predicate.
    pub fn new_random() -> Self {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let predicate = PredicateKey::new(
            PredicateTypeId::Bip340Schnorr,
            signing_key.verifying_key().to_bytes().to_vec(),
        );
        Self {
            signing_key,
            predicate,
        }
    }
}

/// Creates a [`MohoState`] with a deterministic inner state derived from `id`.
pub fn create_state(id: u8, predicate: PredicateKey) -> MohoState {
    let inner_state = moho_types::InnerStateCommitment::from([id; 32]);
    let export_state = moho_types::ExportState::new(vec![]).unwrap();
    MohoState::new(inner_state, predicate, export_state)
}

/// Creates a [`StateRefAttestation`] for the given `id` and `state`.
pub fn attestation(id: u8, state: &MohoState) -> StateRefAttestation {
    let commitment = state.compute_commitment();
    let reference = StateReference::from([id; 32]);
    StateRefAttestation::new(reference, commitment)
}

/// Creates a Merkle inclusion proof for the predicate within the given state.
pub fn create_predicate_inclusion_proof(state: &MohoState) -> MerkleProofB32 {
    let leaves = vec![
        <_ as TreeHash<TreeSha256Hasher>>::tree_hash_root(&state.inner_state).into_inner(),
        <_ as TreeHash<TreeSha256Hasher>>::tree_hash_root(&state.next_predicate).into_inner(),
        <_ as TreeHash<TreeSha256Hasher>>::tree_hash_root(&state.export_state).into_inner(),
        [0u8; 32],
    ];

    let generic_proof = BinaryMerkleTree::from_leaves::<Sha256NoPrefixHasher>(leaves)
        .expect("valid tree")
        .gen_proof(1)
        .expect("proof exists");
    MerkleProofB32::from_generic(&generic_proof)
}

/// Creates a [`StepMohoAttestation`] between two states identified by `from`/`to` IDs.
pub fn step_attestation(
    from: u8,
    to: u8,
    from_state: &MohoState,
    to_state: &MohoState,
) -> StepMohoAttestation {
    StepMohoAttestation::new(attestation(from, from_state), attestation(to, to_state))
}

/// Signs a [`StepMohoAttestation`] with the given signing key.
pub fn sign_attestation(att: &StepMohoAttestation, signing_key: &SigningKey) -> Vec<u8> {
    signing_key.sign(&ssz_encode(att)).to_bytes().to_vec()
}

/// Creates a [`StepMohoProof`] and its corresponding Merkle inclusion proof.
pub fn step_proof_with_merkle(
    from: u8,
    to: u8,
    from_state: &MohoState,
    to_state: &MohoState,
    signing_key: &SigningKey,
) -> (StepMohoProof, MerkleProofB32) {
    let att = step_attestation(from, to, from_state, to_state);
    let signature = sign_attestation(&att, signing_key);
    let proof = StepMohoProof::new(att, signature);
    let merkle_proof = create_predicate_inclusion_proof(from_state);
    (proof, merkle_proof)
}

/// Creates a complete [`MohoRecursiveInput`] for testing.
///
/// If `prev` is `Some((f, t))`, a previous recursive proof transitioning from `f` to `t`
/// is included, signed with the `moho` predicate's signing key.
pub fn create_input(
    from: u8,
    to: u8,
    prev: Option<(u8, u8)>,
    moho: &SchnorrPredicate,
    step: &SchnorrPredicate,
) -> MohoRecursiveInput {
    let from_state = create_state(from, step.predicate.clone());
    let to_state = create_state(to, step.predicate.clone());
    let (step_proof, step_predicate_merkle_proof) =
        step_proof_with_merkle(from, to, &from_state, &to_state, &step.signing_key);

    let prev_recursive_proof = prev.map(|(f, t)| {
        let prev_from_state = create_state(f, step.predicate.clone());
        let prev_to_state = create_state(t, step.predicate.clone());
        let rec_att = RecursiveMohoAttestation::new(
            attestation(f, &prev_from_state),
            attestation(t, &prev_to_state),
        );
        let output = MohoRecursiveOutput::new(rec_att.clone(), moho.predicate.clone());
        let signature = moho.signing_key.sign(&ssz_encode(&output)).to_bytes().to_vec();
        RecursiveMohoProof::new(rec_att, signature)
    });

    MohoRecursiveInput {
        moho_predicate: moho.predicate.clone(),
        prev_recursive_proof,
        incremental_step_proof: step_proof,
        step_predicate: step.predicate.clone(),
        step_predicate_merkle_proof,
    }
}

/// Creates the expected [`StepMohoAttestation`] for a given `from`/`to` pair and predicate.
pub fn expected_attestation(from: u8, to: u8, predicate: &PredicateKey) -> StepMohoAttestation {
    let from_state = create_state(from, predicate.clone());
    let to_state = create_state(to, predicate.clone());
    step_attestation(from, to, &from_state, &to_state)
}
