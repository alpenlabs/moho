//! Reference types.

use borsh::{BorshDeserialize, BorshSerialize};

macro_rules! inst_id {
    ($name:ident) => {
        #[derive(Copy, Clone, Eq, PartialEq, Default, BorshDeserialize, BorshSerialize)]
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

        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                // twice as large, required by the hex::encode_to_slice.
                let mut buf = [0; 64];
                ::hex::encode_to_slice(self.0, &mut buf).expect("buf: enc hex");
                f.write_str(unsafe { ::core::str::from_utf8_unchecked(&buf) })
            }
        }
    };
}

inst_id!(StateReference);
inst_id!(InnerStateCommitment);
inst_id!(MohoStateCommitment);
