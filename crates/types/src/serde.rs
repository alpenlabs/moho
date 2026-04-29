//! Serde serialization and deserialization for moho types.
//!
//! This module is gated on the `serde` feature. It implements `Serialize` and `Deserialize`
//! using different strategies based on whether the format is human-readable.
//!
//! ## Commitment / reference types ([`StateReference`], [`InnerStateCommitment`],
//! [`MohoStateCommitment`])
//!
//! Each is a 32-byte newtype.
//!
//! - **Human-readable** (JSON, TOML, …): `0x`-prefixed lowercase hex string of the 32 bytes.
//! - **Binary** (bincode, postcard, …): raw 32-byte slice.
//!
//! ## SSZ container types ([`MohoState`], [`ExportState`], [`ExportContainer`])
//!
//! - **Human-readable**: structured field-by-field representation. `FixedBytes<32>` fields are
//!   emitted as `0x`-prefixed lowercase hex strings; `PredicateKey` uses its own serde
//!   representation; the embedded `Mmr64B32` is expanded to `{ entries, roots }`.
//! - **Binary**: raw SSZ wire bytes (`as_ssz_bytes`). This preserves SSZ's canonicality and
//!   field-validation guarantees on round-trip.
//!
//! Implemented via private proxy structs that mirror the generated SSZ shape with serde-friendly
//! field types; the manual `Serialize`/`Deserialize` impls branch on `is_human_readable()` and
//! delegate to either the proxy (human-readable) or `as_ssz_bytes` / `from_ssz_bytes` (binary).

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor};
use ssz::{Decode, Encode};

use crate::{
    ExportContainer, ExportState, InnerStateCommitment, MohoState, MohoStateCommitment,
    StateReference,
};

// -- 32-byte newtype helpers -----------------------------------------------------------------

fn serialize_bytes32<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() {
        s.serialize_str(&const_hex::encode_prefixed(bytes))
    } else {
        s.serialize_bytes(bytes)
    }
}

fn deserialize_bytes32<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = [u8; 32];
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a 32-byte hex string or 32 raw bytes")
        }
        fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
            const_hex::decode_to_array::<_, 32>(s).map_err(E::custom)
        }
        fn visit_bytes<E: serde::de::Error>(self, b: &[u8]) -> Result<Self::Value, E> {
            <[u8; 32]>::try_from(b).map_err(|_| E::invalid_length(b.len(), &self))
        }
        fn visit_byte_buf<E: serde::de::Error>(self, b: Vec<u8>) -> Result<Self::Value, E> {
            self.visit_bytes(&b)
        }
    }
    if d.is_human_readable() {
        d.deserialize_str(V)
    } else {
        d.deserialize_bytes(V)
    }
}

macro_rules! impl_id_serde {
    ($name:ty) => {
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                serialize_bytes32(self.inner(), s)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                deserialize_bytes32(d).map(Self::new)
            }
        }
    };
}

impl_id_serde!(StateReference);
impl_id_serde!(InnerStateCommitment);
impl_id_serde!(MohoStateCommitment);

// -- Human-readable proxy structs for the SSZ container types --------------------------------
//
// These mirror the shape of the generated SSZ types with serde-friendly field types
// (`FixedBytes<32>` → hex string, `Mmr64B32` → expanded struct). The manual
// `Serialize`/`Deserialize` impls below delegate to these proxies when the format is
// human-readable.
//
// Each `From<&Owned>` / `TryFrom<Proxy>` impl destructures the input rather than using field
// access, and constructs the output with explicit field names. Both struct patterns and struct
// constructors are exhaustive in Rust, so adding or removing a field on either the SSZ-generated
// type or the proxy fails to compile here — keeping the two definitions in sync.

mod hr {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use ssz_types::{FixedBytes, VariableList};
    use strata_merkle::Mmr64B32;
    use strata_predicate::PredicateKey;

    use crate::{ExportContainer, ExportState, MohoState};

    /// `FixedBytes<32>` represented as an `0x`-prefixed lowercase hex string.
    #[derive(Copy, Clone)]
    pub(super) struct Hex32(pub FixedBytes<32>);

    impl Serialize for Hex32 {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&const_hex::encode_prefixed(self.0.0))
        }
    }

    impl<'de> Deserialize<'de> for Hex32 {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let s = String::deserialize(d)?;
            let bytes = const_hex::decode_to_array::<_, 32>(s.as_str())
                .map_err(serde::de::Error::custom)?;
            Ok(Hex32(FixedBytes(bytes)))
        }
    }

    #[derive(Serialize, Deserialize)]
    pub(super) struct Mmr64B32Proxy {
        pub entries: u64,
        pub roots: Vec<Hex32>,
    }

    impl From<&Mmr64B32> for Mmr64B32Proxy {
        fn from(m: &Mmr64B32) -> Self {
            let Mmr64B32 { entries, roots } = m;
            Self {
                entries: *entries,
                roots: roots.iter().copied().map(Hex32).collect(),
            }
        }
    }

    impl TryFrom<Mmr64B32Proxy> for Mmr64B32 {
        type Error = String;
        fn try_from(p: Mmr64B32Proxy) -> Result<Self, Self::Error> {
            let Mmr64B32Proxy { entries, roots } = p;
            let roots: Vec<FixedBytes<32>> = roots.into_iter().map(|h| h.0).collect();
            let roots = VariableList::new(roots).map_err(|e| format!("mmr roots: {e:?}"))?;
            Ok(Mmr64B32 { entries, roots })
        }
    }

    #[derive(Serialize, Deserialize)]
    pub(super) struct ExportContainerProxy {
        pub container_id: u8,
        pub extra_data: Hex32,
        pub entries_mmr: Mmr64B32Proxy,
    }

    impl From<&ExportContainer> for ExportContainerProxy {
        fn from(c: &ExportContainer) -> Self {
            let ExportContainer {
                container_id,
                extra_data,
                entries_mmr,
            } = c;
            Self {
                container_id: *container_id,
                extra_data: Hex32(*extra_data),
                entries_mmr: Mmr64B32Proxy::from(entries_mmr),
            }
        }
    }

    impl TryFrom<ExportContainerProxy> for ExportContainer {
        type Error = String;
        fn try_from(p: ExportContainerProxy) -> Result<Self, Self::Error> {
            let ExportContainerProxy {
                container_id,
                extra_data,
                entries_mmr,
            } = p;
            Ok(ExportContainer {
                container_id,
                extra_data: extra_data.0,
                entries_mmr: Mmr64B32::try_from(entries_mmr)?,
            })
        }
    }

    #[derive(Serialize, Deserialize)]
    pub(super) struct ExportStateProxy {
        pub containers: Vec<ExportContainerProxy>,
    }

    impl From<&ExportState> for ExportStateProxy {
        fn from(s: &ExportState) -> Self {
            let ExportState { containers } = s;
            Self {
                containers: containers.iter().map(ExportContainerProxy::from).collect(),
            }
        }
    }

    impl TryFrom<ExportStateProxy> for ExportState {
        type Error = String;
        fn try_from(p: ExportStateProxy) -> Result<Self, Self::Error> {
            let ExportStateProxy { containers } = p;
            let containers: Result<Vec<_>, _> = containers
                .into_iter()
                .map(ExportContainer::try_from)
                .collect();
            let containers = VariableList::new(containers?)
                .map_err(|e| format!("export state containers: {e:?}"))?;
            Ok(ExportState { containers })
        }
    }

    #[derive(Serialize, Deserialize)]
    pub(super) struct MohoStateProxy {
        pub inner_state: Hex32,
        pub next_predicate: PredicateKey,
        pub export_state: ExportStateProxy,
    }

    impl From<&MohoState> for MohoStateProxy {
        fn from(s: &MohoState) -> Self {
            let MohoState {
                inner_state,
                next_predicate,
                export_state,
            } = s;
            Self {
                inner_state: Hex32(*inner_state),
                next_predicate: next_predicate.clone(),
                export_state: ExportStateProxy::from(export_state),
            }
        }
    }

    impl TryFrom<MohoStateProxy> for MohoState {
        type Error = String;
        fn try_from(p: MohoStateProxy) -> Result<Self, Self::Error> {
            let MohoStateProxy {
                inner_state,
                next_predicate,
                export_state,
            } = p;
            Ok(MohoState {
                inner_state: inner_state.0,
                next_predicate,
                export_state: ExportState::try_from(export_state)?,
            })
        }
    }
}

// -- SSZ container types: structured human-readable, raw SSZ bytes for binary ----------------

fn deserialize_ssz_bytes<'de, T: Decode, D: Deserializer<'de>>(d: D) -> Result<T, D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("raw SSZ-encoded bytes")
        }
        fn visit_bytes<E: serde::de::Error>(self, b: &[u8]) -> Result<Self::Value, E> {
            Ok(b.to_vec())
        }
        fn visit_byte_buf<E: serde::de::Error>(self, b: Vec<u8>) -> Result<Self::Value, E> {
            Ok(b)
        }
    }
    let bytes = d.deserialize_bytes(V)?;
    T::from_ssz_bytes(&bytes).map_err(|e| serde::de::Error::custom(format!("ssz decode: {e:?}")))
}

macro_rules! impl_container_serde {
    ($name:ty, $proxy:ty) => {
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    <$proxy>::from(self).serialize(s)
                } else {
                    s.serialize_bytes(&self.as_ssz_bytes())
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                if d.is_human_readable() {
                    let proxy = <$proxy>::deserialize(d)?;
                    <$name>::try_from(proxy).map_err(serde::de::Error::custom)
                } else {
                    deserialize_ssz_bytes(d)
                }
            }
        }
    };
}

impl_container_serde!(MohoState, hr::MohoStateProxy);
impl_container_serde!(ExportState, hr::ExportStateProxy);
impl_container_serde!(ExportContainer, hr::ExportContainerProxy);

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use ssz::Encode;
    use strata_predicate::PredicateKey;

    use super::*;
    use crate::relation::{StateRefAttestation, StepMohoAttestation};

    type Hash32 = [u8; 32];

    fn always_accept() -> PredicateKey {
        PredicateKey {
            id: 1,
            condition: vec![].try_into().unwrap(),
        }
    }

    fn predicate_strategy() -> impl Strategy<Value = PredicateKey> {
        // Restricted to valid `PredicateTypeId` variants: the human-readable serde path
        // for `PredicateKey` rejects unknown ids.
        let valid_ids = prop::sample::select(vec![0u8, 1, 10, 20]);
        (valid_ids, prop::collection::vec(any::<u8>(), 0..8)).prop_map(|(id, condition)| {
            PredicateKey {
                id,
                condition: condition.try_into().unwrap(),
            }
        })
    }

    fn export_container_strategy() -> impl Strategy<Value = ExportContainer> {
        (any::<u8>(), prop::collection::vec(any::<Hash32>(), 0..10)).prop_map(
            |(container_id, entries)| {
                let mut container = ExportContainer::new(container_id);
                for entry in entries {
                    container.add_entry(entry).expect("failed to add entry");
                }
                container
            },
        )
    }

    fn export_state_strategy() -> impl Strategy<Value = ExportState> {
        prop::collection::vec(export_container_strategy(), 0..5)
            .prop_map(|containers| ExportState::new(containers).unwrap())
    }

    fn moho_state_strategy() -> impl Strategy<Value = MohoState> {
        (
            any::<Hash32>(),
            predicate_strategy(),
            export_state_strategy(),
        )
            .prop_map(|(inner_bytes, predicate, export_state)| {
                let inner = InnerStateCommitment::from(inner_bytes);
                MohoState::new(inner, predicate, export_state)
            })
    }

    fn sample_state() -> MohoState {
        let inner = InnerStateCommitment::from([0xAB; 32]);
        let mut container = ExportContainer::new(7);
        container.add_entry([0x11; 32]).unwrap();
        container.add_entry([0x22; 32]).unwrap();
        container.update_extra_data([0xCD; 32]);
        let export = ExportState::new(vec![container]).unwrap();
        MohoState::new(inner, always_accept(), export)
    }

    #[test]
    fn id_json_roundtrip() {
        let id = InnerStateCommitment::from([0xAB; 32]);
        let json = serde_json::to_string(&id).unwrap();
        assert!(
            json.starts_with("\"0x") && json.contains(&"ab".repeat(32)),
            "expected 0x-prefixed hex, got {json}"
        );
        let back: InnerStateCommitment = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn id_bincode_roundtrip() {
        let id = MohoStateCommitment::from([0x42; 32]);
        let bytes = bincode::serialize(&id).unwrap();
        let back: MohoStateCommitment = bincode::deserialize(&bytes).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn moho_state_json_shape() {
        let state = sample_state();
        let value: serde_json::Value = serde_json::to_value(&state).unwrap();
        let obj = value
            .as_object()
            .expect("MohoState JSON should be an object");

        assert_eq!(
            obj.get("inner_state").and_then(|v| v.as_str()),
            Some(format!("0x{}", "ab".repeat(32))).as_deref()
        );
        assert!(obj.contains_key("next_predicate"));

        let containers = obj
            .get("export_state")
            .and_then(|v| v.get("containers"))
            .and_then(|v| v.as_array())
            .expect("containers array");
        assert_eq!(containers.len(), 1);
        let c = &containers[0];
        assert_eq!(c.get("container_id").and_then(|v| v.as_u64()), Some(7));
        assert_eq!(
            c.get("extra_data").and_then(|v| v.as_str()),
            Some(format!("0x{}", "cd".repeat(32))).as_deref()
        );
        let mmr = c.get("entries_mmr").expect("entries_mmr");
        assert_eq!(mmr.get("entries").and_then(|v| v.as_u64()), Some(2));
        assert!(mmr.get("roots").and_then(|v| v.as_array()).is_some());
    }

    #[test]
    fn moho_state_json_roundtrip() {
        let state = sample_state();
        let json = serde_json::to_string(&state).unwrap();
        dbg!(&json);
        let back: MohoState = serde_json::from_str(&json).unwrap();
        assert_eq!(state.compute_commitment(), back.compute_commitment());
        assert_eq!(state.as_ssz_bytes(), back.as_ssz_bytes());
    }

    #[test]
    fn moho_state_bincode_roundtrip() {
        let state = sample_state();
        let bytes = bincode::serialize(&state).unwrap();
        let back: MohoState = bincode::deserialize(&bytes).unwrap();
        assert_eq!(state.as_ssz_bytes(), back.as_ssz_bytes());
    }

    #[test]
    fn export_state_roundtrip_both_formats() {
        let state = sample_state();
        let export = state.export_state().clone();

        let json = serde_json::to_string(&export).unwrap();
        let json_back: ExportState = serde_json::from_str(&json).unwrap();
        assert_eq!(export.as_ssz_bytes(), json_back.as_ssz_bytes());

        let bin = bincode::serialize(&export).unwrap();
        let bin_back: ExportState = bincode::deserialize(&bin).unwrap();
        assert_eq!(export.as_ssz_bytes(), bin_back.as_ssz_bytes());
    }

    #[test]
    fn export_container_roundtrip_both_formats() {
        let mut container = ExportContainer::new(3);
        container.add_entry([0xFE; 32]).unwrap();

        let json = serde_json::to_string(&container).unwrap();
        let json_back: ExportContainer = serde_json::from_str(&json).unwrap();
        assert_eq!(container.as_ssz_bytes(), json_back.as_ssz_bytes());

        let bin = bincode::serialize(&container).unwrap();
        let bin_back: ExportContainer = bincode::deserialize(&bin).unwrap();
        assert_eq!(container.as_ssz_bytes(), bin_back.as_ssz_bytes());
    }

    #[test]
    fn relation_struct_json_shape() {
        let attest = StateRefAttestation::new(
            StateReference::from([1u8; 32]),
            MohoStateCommitment::from([2u8; 32]),
        );
        let json = serde_json::to_string(&attest).unwrap();
        assert!(json.contains("\"reference\""));
        assert!(json.contains("\"commitment\""));
        assert!(json.contains(&format!("0x{}", "01".repeat(32))));
        assert!(json.contains(&format!("0x{}", "02".repeat(32))));

        let back: StateRefAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(attest, back);
    }

    #[test]
    fn step_attestation_roundtrip() {
        let from = StateRefAttestation::new(
            StateReference::from([0xAA; 32]),
            MohoStateCommitment::from([0xBB; 32]),
        );
        let to = StateRefAttestation::new(
            StateReference::from([0xCC; 32]),
            MohoStateCommitment::from([0xDD; 32]),
        );
        let step = StepMohoAttestation::new(from, to);

        let json = serde_json::to_string(&step).unwrap();
        let back: StepMohoAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(step, back);

        let bin = bincode::serialize(&step).unwrap();
        let back: StepMohoAttestation = bincode::deserialize(&bin).unwrap();
        assert_eq!(step, back);
    }

    proptest! {
        #[test]
        fn json_roundtrip_proptest(state in moho_state_strategy()) {
            let json = serde_json::to_string(&state).unwrap();
            let back: MohoState = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(state.as_ssz_bytes(), back.as_ssz_bytes());
        }

        #[test]
        fn bincode_roundtrip_proptest(state in moho_state_strategy()) {
            let bytes = bincode::serialize(&state).unwrap();
            let back: MohoState = bincode::deserialize(&bytes).unwrap();
            prop_assert_eq!(state.as_ssz_bytes(), back.as_ssz_bytes());
        }
    }
}
