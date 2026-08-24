use std::path::Path;

use lenso_contract_codegen::check_projection;

fn main() {
    println!("cargo:rerun-if-changed=capability.json");
    println!("cargo:rerun-if-changed=schemas");
    println!("cargo:rerun-if-changed=src/generated.rs");
    check_projection(
        Path::new("capability.json"),
        lenso_contract_codegen::ProjectionLanguage::Rust,
        Path::new("src/generated.rs"),
    )
    .expect("Identity Directory generated artifacts are stale");
}
