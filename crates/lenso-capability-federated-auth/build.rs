use std::path::Path;
fn main() {
    println!("cargo:rerun-if-changed=capability.json");
    println!("cargo:rerun-if-changed=schemas");
    lenso_contract_codegen::check_projection(
        Path::new("capability.json"),
        lenso_contract_codegen::ProjectionLanguage::Rust,
        Path::new("src/generated.rs"),
    )
    .expect("generated Capability artifacts are stale");
}
