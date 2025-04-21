//! Reference types.

use borsh::{BorshDeserialize, BorshSerialize};

macro_rules! inst_id {
    ($name:ident) => {
        #[derive(Copy, Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn new(inner: [u8; 32]) -> Self {
                Self(inner)
            }

            pub fn inner(&self) -> &[u8; 32] {
                &self.0
            }

            pub fn into_inner(self) -> [u8; 32] {
                self.0
            }
        }
    };
}

inst_id!(StateReference);
inst_id!(InnerStateCommitment);
inst_id!(MohoStateCommitment);
