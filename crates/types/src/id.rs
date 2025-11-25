//! Reference types.

use borsh::{BorshDeserialize, BorshSerialize};
use ssz_types::FixedBytes;

macro_rules! inst_id {
    ($name:ident) => {
        #[derive(Copy, Clone, Eq, PartialEq)]
        pub struct $name(FixedBytes<32>);

        impl $name {
            pub fn new(inner: [u8; 32]) -> Self {
                Self(FixedBytes::from(inner))
            }

            pub fn inner(&self) -> &FixedBytes<32> {
                &self.0
            }

            pub fn into_inner(self) -> FixedBytes<32> {
                self.0
            }

            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_ref()
            }

            pub fn as_array(&self) -> &[u8; 32] {
                // FixedBytes<32> internally stores [u8; 32]
                unsafe { &*(self.0.as_ref().as_ptr() as *const [u8; 32]) }
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

        impl BorshSerialize for $name {
            fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
                writer.write_all(self.0.as_ref())
            }
        }

        impl BorshDeserialize for $name {
            fn deserialize_reader<R: borsh::io::Read>(
                reader: &mut R,
            ) -> borsh::io::Result<Self> {
                let mut bytes = [0u8; 32];
                reader.read_exact(&mut bytes)?;
                Ok(Self(FixedBytes::from(bytes)))
            }
        }

        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                // twice as large, required by the hex::encode_to_slice.
                let mut buf = [0; 64];
                ::hex::encode_to_slice(self.0.as_ref(), &mut buf).expect("buf: enc hex");
                f.write_str(unsafe { ::core::str::from_utf8_unchecked(&buf) })
            }
        }
    };
}

inst_id!(StateReference);
inst_id!(InnerStateCommitment);
inst_id!(MohoStateCommitment);
