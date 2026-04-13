//! Test utilities for constructing Moho proofs, states, and transitions.
use k256::schnorr::{SigningKey, signature::Signer};
use moho_types::{MohoState, StateRefAttestation, StateReference};
use rand_core::OsRng;
use ssz::ssz_encode;
use strata_merkle::{BinaryMerkleTree, MerkleProofB32, Sha256NoPrefixHasher};
use strata_predicate::{PredicateKey, PredicateTypeId};
use tree_hash::{Sha256Hasher as TreeSha256Hasher, TreeHash};

use crate::{
    io::MohoRecursiveInput,
    transition::{MohoStateTransition, MohoTransitionWithProof, Transition},
};

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
        let signing_key = SigningKey::random(&mut OsRng);
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

/// Creates a [`MohoStateTransition`] between two states identified by `from`/`to` IDs.
pub fn transition_with_predicate(
    from: u8,
    to: u8,
    from_state: &MohoState,
    to_state: &MohoState,
) -> MohoStateTransition {
    Transition::new(attestation(from, from_state), attestation(to, to_state))
}

/// Signs a [`MohoStateTransition`] with the given signing key.
pub fn sign_transition(transition: &MohoStateTransition, signing_key: &SigningKey) -> Vec<u8> {
    signing_key
        .sign(&ssz_encode(transition))
        .to_bytes()
        .to_vec()
}

/// Creates a [`MohoTransitionWithProof`] and its corresponding Merkle inclusion proof.
pub fn transition_with_proof(
    from: u8,
    to: u8,
    from_state: &MohoState,
    to_state: &MohoState,
    signing_key: &SigningKey,
) -> (MohoTransitionWithProof, MerkleProofB32) {
    let transition = transition_with_predicate(from, to, from_state, to_state);
    let signature = sign_transition(&transition, signing_key);
    let proof = MohoTransitionWithProof::new(transition, signature);
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
        transition_with_proof(from, to, &from_state, &to_state, &step.signing_key);

    let prev_recursive_proof = prev.map(|(f, t)| {
        let prev_from_state = create_state(f, step.predicate.clone());
        let prev_to_state = create_state(t, step.predicate.clone());
        let transition = transition_with_predicate(f, t, &prev_from_state, &prev_to_state);
        let signature = sign_transition(&transition, &moho.signing_key);
        MohoTransitionWithProof::new(transition, signature)
    });

    MohoRecursiveInput {
        moho_predicate: moho.predicate.clone(),
        prev_recursive_proof,
        incremental_step_proof: step_proof,
        step_predicate: step.predicate.clone(),
        step_predicate_merkle_proof,
    }
}

/// Creates the expected [`MohoStateTransition`] for a given `from`/`to` pair and predicate.
pub fn expected_transition(from: u8, to: u8, predicate: &PredicateKey) -> MohoStateTransition {
    let from_state = create_state(from, predicate.clone());
    let to_state = create_state(to, predicate.clone());
    transition_with_predicate(from, to, &from_state, &to_state)
}
