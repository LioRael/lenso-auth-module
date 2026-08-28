//! Portable identity-directory role used by concrete Auth Plugins.

#[allow(dead_code)]
mod contract;

mod generated {
    include!("generated.rs");
}

pub use generated::*;
