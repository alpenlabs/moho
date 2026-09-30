//! Public ELF path exports produced by this crate's build script.
//!
//! The ELF is emitted into `<crate>/elfs/` (see `build.rs`); the constant
//! below points at that stable path rather than into cargo's `target/`.

/// Path to the compiled Moho recursive proof guest ELF.
pub const MOHO_ELF_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/elfs/moho.elf");
