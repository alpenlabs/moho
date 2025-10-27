//! SSZ container-field inclusion helpers.
//!
//! Minimal helper to generate and verify inclusion proofs for SSZ container
//! field roots using SHA-256 over 32-byte chunks with zero-chunk padding to the
//! next power of two. Internal nodes are computed as sha256(left || right).
//!
//! What this is:
//! - Proving inclusion of a field root within a container's SSZ tree-hash root.
//!
//! What this is NOT:
//! - A generalized-index (gindex) proof. We use a simple 0-based leaf index.
//! - A proof for list element membership. For lists, the leaf must be the SSZ field root of the
//!   entire list (including any mix-in length), not an element.

use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

/// Inclusion proof for an SSZ-merkelized leaf (field root) under a container root.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct SszLeafInclusionProof {
    /// Bottom-up list of sibling hashes required to reconstruct the root.
    /// The first entry is adjacent to the leaf level.
    pub branch: Vec<[u8; 32]>,
    /// 0-based index of the leaf in the bottom layer. Not a generalized index.
    pub leaf_index: u8,
}

/// SSZ field-merkleization utilities (stateless; no persistent tree structure).
pub struct SszFieldMerkle;

/// Trait exposing per-field SSZ roots for a container.
///
/// This is a lightweight, local convenience so callers can generate inclusion
/// proofs without manually assembling the field-root slice. If you control the
/// SSZ codegen (recommended), prefer emitting an inherent `ssz_field_roots()`
/// method from the generator instead of implementing this trait by hand.
pub trait SszFieldRoots {
    /// Return SSZ field roots in container field order.
    fn ssz_field_roots(&self) -> Vec<[u8; 32]>;
}

impl SszFieldMerkle {
    /// Generate Merkle path for a specific leaf index
    pub fn generate_proof(leaves: &[[u8; 32]], leaf_index: usize) -> SszLeafInclusionProof {
        let branch = Self::build_branch(leaves, leaf_index);

        SszLeafInclusionProof {
            branch,
            leaf_index: leaf_index as u8,
        }
    }

    /// Generate a proof from a container by computing its field roots.
    pub fn generate_proof_for_container<C: SszFieldRoots>(
        container: &C,
        field_index: usize,
    ) -> SszLeafInclusionProof {
        let leaves = container.ssz_field_roots();
        Self::generate_proof(&leaves, field_index)
    }

    /// Verify a Merkle proof
    pub fn verify_proof(
        root: &[u8; 32],
        proof: &SszLeafInclusionProof,
        leaf_value: &[u8; 32],
    ) -> bool {
        let mut current_hash = *leaf_value;
        let mut current_index = proof.leaf_index as usize;

        for sibling in &proof.branch {
            if current_index.is_multiple_of(2) {
                // Current node is left child
                current_hash = Self::hash_internal(&current_hash, sibling);
            } else {
                // Current node is right child
                current_hash = Self::hash_internal(sibling, &current_hash);
            }
            current_index /= 2;
        }

        current_hash == *root
    }

    /// Build the bottom-up sibling branch for a given leaf index.
    fn build_branch(leaves: &[[u8; 32]], leaf_index: usize) -> Vec<[u8; 32]> {
        let mut branch = Vec::new();
        let mut current_level = leaves.to_vec();
        let mut current_index = leaf_index;

        // Pad to next power of 2
        let next_pow2 = current_level.len().next_power_of_two();
        current_level.resize(next_pow2, [0u8; 32]);

        // Build path bottom-up
        while current_level.len() > 1 {
            let sibling_index = if current_index.is_multiple_of(2) {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < current_level.len() {
                branch.push(current_level[sibling_index]);
            } else {
                branch.push([0u8; 32]);
            }

            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = current_level.get(i + 1).copied().unwrap_or([0u8; 32]);
                next_level.push(Self::hash_internal(&left, &right));
            }

            current_level = next_level;
            current_index /= 2;
        }

        branch
    }

    /// Hash two internal nodes: sha256(left || right)
    fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use ssz_types::{FixedVector, VariableList};
    use tree_hash::{Sha256Hasher, TreeHash};

    use super::*;

    #[derive(Clone, Debug, tree_hash_derive::TreeHash)]
    struct Simple3 {
        a: FixedVector<u8, 32>,
        b: FixedVector<u8, 32>,
        c: FixedVector<u8, 32>,
    }

    #[derive(Clone, Debug, tree_hash_derive::TreeHash)]
    struct WithList {
        head: FixedVector<u8, 32>,
        data: VariableList<u8, 256>,
        tail: FixedVector<u8, 32>,
    }

    #[derive(Clone, Debug, tree_hash_derive::TreeHash)]
    struct Nested {
        left: Simple3,
        payload: WithList,
        right: FixedVector<u8, 32>,
    }

    // No direct leaf hashing tests; SSZ packing is done at callsites.

    #[test]
    fn test_ssz_simple3_container_root_and_proofs() {
        let c = Simple3 {
            a: FixedVector::from([0x11u8; 32]),
            b: FixedVector::from([0x22u8; 32]),
            c: FixedVector::from([0x33u8; 32]),
        };

        // SSZ root via TreeHash
        let ssz_root = <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&c).into_inner();

        // Build proofs against the SSZ root using field roots as leaves
        let leaves = vec![
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&c.a).into_inner(),
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&c.b).into_inner(),
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&c.c).into_inner(),
        ];
        // Proofs for each field against SSZ root
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = SszFieldMerkle::generate_proof(&leaves, i);
            assert!(SszFieldMerkle::verify_proof(&ssz_root, &proof, leaf));
        }
    }

    #[test]
    fn test_ssz_withlist_container_root_and_proofs() {
        let data_vec = vec![1u8, 3, 3, 7, 0, 9, 9];
        let c = WithList {
            head: FixedVector::from([0xAAu8; 32]),
            data: VariableList::<u8, 256>::from(data_vec),
            tail: FixedVector::from([0xBBu8; 32]),
        };

        let ssz_root = <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&c).into_inner();
        let leaves = vec![
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&c.head).into_inner(),
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&c.data).into_inner(),
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&c.tail).into_inner(),
        ];
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = SszFieldMerkle::generate_proof(&leaves, i);
            assert!(SszFieldMerkle::verify_proof(&ssz_root, &proof, leaf));
        }
    }

    #[test]
    fn test_ssz_nested_container_root_and_proofs() {
        let left = Simple3 {
            a: FixedVector::from([0x01u8; 32]),
            b: FixedVector::from([0x02u8; 32]),
            c: FixedVector::from([0x03u8; 32]),
        };
        let data_vec = vec![1u8, 3, 3, 7, 0, 9, 9];
        let payload = WithList {
            head: FixedVector::from([0xAAu8; 32]),
            data: VariableList::<u8, 256>::from(data_vec),
            tail: FixedVector::from([0xBBu8; 32]),
        };
        let right = FixedVector::from([0xFFu8; 32]);
        let cont = Nested {
            left,
            payload,
            right,
        };

        let ssz_root = <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&cont).into_inner();
        let leaves = vec![
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&cont.left).into_inner(),
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&cont.payload).into_inner(),
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&cont.right).into_inner(),
        ];
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = SszFieldMerkle::generate_proof(&leaves, i);
            assert!(SszFieldMerkle::verify_proof(&ssz_root, &proof, leaf));
        }
    }
}
