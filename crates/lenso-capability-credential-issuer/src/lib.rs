//! Portable credential-issuance role for interactive Auth methods.

#[allow(dead_code)]
mod contract;

mod generated {
    include!("generated.rs");
}

pub use generated::*;
