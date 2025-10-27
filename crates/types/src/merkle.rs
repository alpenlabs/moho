//! SSZ-compatible Merkle helpers used for inclusion proofs of SSZ field roots.
//!
//! This module implements a minimal Merkle tree helper using SHA-256 over 32-byte chunks
//! and zero-chunk padding, matching SSZ merkleization of container field roots.

use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

/// Merkle proof for proving membership of a field in a state structure
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MerkleProof {
    /// The merkle path (sibling hashes) needed to reconstruct the root
    pub path: Vec<[u8; 32]>,
    /// The index of the leaf in the tree
    pub leaf_index: u8,
}

/// Merkle tree builder and utilities
pub struct MerkleTree;

impl MerkleTree {
    /// Compute Merkle root from a list of leaf hashes
    pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }

        let mut current_level = leaves.to_vec();

        // Pad to next power of 2
        let next_pow2 = current_level.len().next_power_of_two();
        current_level.resize(next_pow2, [0u8; 32]);

        // Build tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = current_level.get(i + 1).copied().unwrap_or([0u8; 32]);
                next_level.push(Self::hash_internal(&left, &right));
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Generate Merkle path for a specific leaf index
    pub fn generate_proof(leaves: &[[u8; 32]], leaf_index: usize) -> MerkleProof {
        let path = Self::generate_merkle_path(leaves, leaf_index);

        MerkleProof {
            path,
            leaf_index: leaf_index as u8,
        }
    }

    /// Verify a Merkle proof
    pub fn verify_proof(root: &[u8; 32], proof: &MerkleProof, leaf_value: &[u8; 32]) -> bool {
        let mut current_hash = *leaf_value;
        let mut current_index = proof.leaf_index as usize;

        for sibling in &proof.path {
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

    /// Generate Merkle path for a specific leaf index
    fn generate_merkle_path(leaves: &[[u8; 32]], leaf_index: usize) -> Vec<[u8; 32]> {
        let mut path = Vec::new();
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
                path.push(current_level[sibling_index]);
            } else {
                path.push([0u8; 32]);
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

        path
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

    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaves = vec![[1u8; 32]];
        let root = MerkleTree::compute_root(&leaves);

        let proof = MerkleTree::generate_proof(&leaves, 0);
        assert!(MerkleTree::verify_proof(&root, &proof, &leaves[0]));
    }

    #[test]
    fn test_merkle_tree_three_leaves() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let root = MerkleTree::compute_root(&leaves);

        // Test proof for each leaf
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = MerkleTree::generate_proof(&leaves, i);
            assert!(MerkleTree::verify_proof(&root, &proof, leaf));
        }
    }

    #[test]
    fn test_merkle_tree_power_of_two() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let root = MerkleTree::compute_root(&leaves);

        // Test proof for each leaf
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = MerkleTree::generate_proof(&leaves, i);
            assert!(MerkleTree::verify_proof(&root, &proof, leaf));
        }
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

        // Manual merkleization over field roots
        let leaves = vec![
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&c.a).into_inner(),
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&c.b).into_inner(),
            <_ as TreeHash<Sha256Hasher>>::tree_hash_root(&c.c).into_inner(),
        ];
        let manual_root = MerkleTree::compute_root(&leaves);
        assert_eq!(ssz_root, manual_root);

        // Proofs for each field
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = MerkleTree::generate_proof(&leaves, i);
            assert!(MerkleTree::verify_proof(&ssz_root, &proof, leaf));
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
        let manual_root = MerkleTree::compute_root(&leaves);
        assert_eq!(ssz_root, manual_root);

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = MerkleTree::generate_proof(&leaves, i);
            assert!(MerkleTree::verify_proof(&ssz_root, &proof, leaf));
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
        let manual_root = MerkleTree::compute_root(&leaves);
        assert_eq!(ssz_root, manual_root);

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = MerkleTree::generate_proof(&leaves, i);
            assert!(MerkleTree::verify_proof(&ssz_root, &proof, leaf));
        }
    }
}
