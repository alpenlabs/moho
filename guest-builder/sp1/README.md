# moho-sp1-guest-builder

This crate builds the SP1 guest for the recursive Moho proof. The guest code is
in `guest-moho` and wraps `crates/recursive-proof`. The build script writes the
guest ELF and two files derived from its verifying key to `generated/`.

This directory is its own Cargo workspace, so the SP1 crates stay out of the
root workspace and its lockfile. Run every command below from
`guest-builder/sp1`.

## Prerequisites

- **Rust.** The toolchain pinned in the root `rust-toolchain.toml`.
- **SP1 toolchain.** Install it with `sp1up` and pin it to the same version as
  the SP1 crates in `Cargo.lock` (currently `v6.8.1`):

  ```bash
  curl -fsSL https://sp1.succinct.xyz | bash
  sp1up -v v6.8.1
  cargo prove --version
  ```

  This also installs the `succinct` Rust toolchain that compiles the guest.
- **protoc.** Some guest dependencies compile protobuf files.
- **Docker.** Needed for the `docker-build` feature. Release builds use it, so
  you need Docker to reproduce a released ELF. The Docker daemon must be
  running.

When you bump the SP1 crates, also bump `SP1_VERSION` in
`.github/workflows/guest.yml` and `.github/workflows/release.yml`.

## Outputs

All files land in `generated/`. It is gitignored.

| File                 | Contents                                                        |
|----------------------|-----------------------------------------------------------------|
| `moho.elf`           | The compiled guest program.                                     |
| `moho-predicate.txt` | The SP1 Groth16 predicate, as `Sp1Groth16:<hex>`.               |
| `moho-vkey-hash.txt` | SP1's program vkey hash, as `0x<hex>`.                          |

The predicate is the trust anchor for Moho proofs. Consumers such as the bridge
read it with `PredicateKey::from_str`. The vkey hash is inside the predicate,
but you can't read it without decoding the verifier bytes, so it gets its own
file. It is the same value `cargo prove vkey` prints for the ELF.

The two text files have no trailing newline. Consumers pass the file contents
straight to `from_str`, which rejects a newline. Don't edit them by hand.

Rust code can find the ELF through `MOHO_ELF_PATH` in `src/lib.rs`.

## Building

Both steps are opt-in, because both are slow. A plain `cargo build` compiles
the crate and skips them.

Build the ELF only:

```bash
BUILD_ELF=1 cargo build --locked
```

Build the ELF, the predicate and the vkey hash:

```bash
BUILD_VKEY=1 cargo build --locked
```

`BUILD_VKEY` implies `BUILD_ELF`, since the vk is derived from the ELF.

### Reproducible builds

By default the guest compiles with your local SP1 toolchain. The result can
differ from machine to machine. To get the same ELF as a release, compile
inside SP1's Docker image:

```bash
BUILD_VKEY=1 cargo build --locked --features docker-build
```

Only the guest compile runs in Docker. The vk is still derived on the host.

### Things to watch out for

- `generated/` survives `cargo clean`. A build without the flags leaves old
  files in place, and they may not match the current source. Rebuild before
  you use them.
- `cargo clippy` never builds the guest, whatever flags are set.
- On macOS, the build script points `AR` at the SP1 toolchain's `llvm-ar`.
  macOS's own `ar` produces archives that fail to link in the guest. You don't
  need to do anything, but this is why `rustc +succinct` must work.

## Releases

Pushing a `v*` tag runs `.github/workflows/release.yml`. It builds with
`BUILD_VKEY=1` and `docker-build`, then attaches these files to the GitHub
release:

- `moho.elf`
- `moho-predicate.txt`
- `moho-vkey-hash.txt`
- `SHA256SUMS`

The release notes also show the vkey hash, so you can read it without
downloading anything.

`.github/workflows/guest.yml` builds the ELF on every PR, so a change that
breaks the zkVM build fails there and not at release time.

## Checking a release

Download the release files into one directory, then check the hashes:

```bash
sha256sum -c SHA256SUMS
```

Older macOS releases don't ship `sha256sum`. Use `shasum -a 256 -c SHA256SUMS`
there instead.

Check that the vkey hash matches the ELF:

```bash
cargo prove vkey --elf moho.elf
cat moho-vkey-hash.txt
```

To check that the ELF matches the source, check out the release tag and do a
[reproducible build](#reproducible-builds). Then compare
`generated/moho.elf` with the released one.
