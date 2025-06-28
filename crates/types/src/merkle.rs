//! Merkle tree implementation for state proofs
//!
//! NOTE: This is a temporary implementation using SHA256 and Borsh serialization.
//! This will eventually be reworked to use SSZ (Simple Serialize) serialization
//! and merkelization for better compatibility with Ethereum consensus layer standards
//! and more efficient proof generation/verification.

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
            if current_index % 2 == 0 {
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

    /// Hash a leaf value with domain separation
    pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"LEAF:");
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Hash a serializable value as a leaf
    pub fn hash_serializable<T: BorshSerialize>(value: &T) -> [u8; 32] {
        let serialized = borsh::to_vec(value).expect("Serialization should not fail");
        Self::hash_leaf(&serialized)
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
            let sibling_index = if current_index % 2 == 0 {
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

    /// Hash two internal nodes with domain separation
    fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"INTERNAL:");
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_hash_serializable() {
        #[derive(BorshSerialize)]
        struct TestStruct {
            value: u32,
        }

        let test_data = TestStruct { value: 42 };
        let hash1 = MerkleTree::hash_serializable(&test_data);
        let hash2 = MerkleTree::hash_serializable(&test_data);

        // Same data should produce same hash
        assert_eq!(hash1, hash2);

        let different_data = TestStruct { value: 43 };
        let hash3 = MerkleTree::hash_serializable(&different_data);

        // Different data should produce different hash
        assert_ne!(hash1, hash3);
    }
}
