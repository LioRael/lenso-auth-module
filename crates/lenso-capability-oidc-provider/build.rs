use std::path::Path;
fn main() {
    println!("cargo:rerun-if-changed=capability.json");
    println!("cargo:rerun-if-changed=schemas");
    lenso_contract_codegen::check_generated(
        Path::new("capability.json"),
        Path::new("src/generated.rs"),
        Path::new("generated/bindings.ts"),
    )
    .expect("generated Capability artifacts are stale");
}
