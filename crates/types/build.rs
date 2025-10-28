use std::path::Path;

fn main() {
    // Generate SSZ types for Moho into OUT_DIR
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo");
    let output_path = Path::new(&out_dir).join("generated_ssz.rs");

    // Use local ssz-gen codegen
    let entry_points = ["moho.ssz"]; // ssz/moho.ssz
    let base_dir = "ssz/"; // relative to this crate root
    let crates: [&str; 0] = [];

    ssz_codegen::build_ssz_files(
        &entry_points,
        base_dir,
        &crates,
        output_path.to_str().expect("utf8 path"),
        ssz_codegen::ModuleGeneration::NestedModules,
    )
    .expect("Failed to generate SSZ types");

    // Post-process: add common Rust derives to generated structs for ergonomics.
    // This augments `#[derive(Encode, Decode, TreeHash)]` to also include `Clone, Debug`.
    let mut code = std::fs::read_to_string(&output_path).expect("read generated ssz");
    // Conservative, exact replacement to avoid unintended edits.
    code = code.replace(
        "#[derive(Encode, Decode, TreeHash)]",
        "#[derive(Clone, Debug, Encode, Decode, TreeHash)]",
    );
    std::fs::write(&output_path, code).expect("write patched generated ssz");
}
