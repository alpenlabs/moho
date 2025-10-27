//! Moho schema constants.

/// The maximum number of containers in the export state.
pub const MAX_EXPORT_CONTAINERS: usize = 256;

/// The maximum number of entries in each container.
pub const MAX_EXPORT_ENTRIES: usize = 1 << 12; // 4096

/// The maximum size in bytes of an export payload (either on the container or an entry).
pub const MAX_PAYLOAD_SIZE: usize = 1 << 12; // 4096

/// The maximum size in bytes of the encoded predicate key used in SSZ state (borsh-encoded bytes).
pub const MAX_PREDICATE_SIZE: usize = 256;
