// SPDX-License-Identifier: Apache-2.0

//! cpop_protocol: Core Rust implementation of the Proof-of-Process (CPoP) Protocol.
//!
//! This crate provides the foundational types and cryptographic logic for the CPoP protocol,
//! ensuring compliance with IETF Rats working group specifications.

pub mod baseline;
pub mod c2pa;
pub mod codec;
pub mod crypto;
pub mod error;
pub mod evidence;
pub mod forensics;
pub mod identity;
pub mod rfc;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use crate::error::{Error, Result};

/// Current CPoP protocol version number.
pub const PROTOCOL_VERSION: u32 = 1;
