//! Portable identity-directory role used by concrete Auth Modules.

#[allow(dead_code)]
mod contract;

mod generated {
    include!("generated.rs");
}

pub use generated::*;
