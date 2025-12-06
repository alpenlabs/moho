//! Reference types.

use ssz_derive::{Decode, Encode};
use ssz_types::FixedBytes;

macro_rules! inst_id {
    ($name:ident) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Encode, Decode)]
        #[ssz(struct_behaviour = "transparent")]
        pub struct $name(FixedBytes<32>);

        impl $name {
            pub fn new(inner: [u8; 32]) -> Self {
                Self(FixedBytes::from(inner))
            }

            pub fn inner(&self) -> &[u8; 32] {
                // FixedBytes<32> internally stores [u8; 32]
                unsafe { &*(self.0.as_ref().as_ptr() as *const [u8; 32]) }
            }

            pub fn into_inner(self) -> [u8; 32] {
                self.0.into_inner()
            }

            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self(FixedBytes::from([0u8; 32]))
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self(FixedBytes::from(bytes))
            }
        }

        impl From<FixedBytes<32>> for $name {
            fn from(inner: FixedBytes<32>) -> Self {
                Self(FixedBytes::from(inner))
            }
        }
    };
}

inst_id!(StateReference);
inst_id!(InnerStateCommitment);
inst_id!(MohoStateCommitment);
