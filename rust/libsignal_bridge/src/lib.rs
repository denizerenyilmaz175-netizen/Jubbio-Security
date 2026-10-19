//! Jubbio's libsignal FFI boundary.
//!
//! This crate intentionally has no fallback cryptography. Before production use,
//! pin a reviewed libsignal release and implement the FFI with the exact API of
//! that release. Returning an error is safer than silently using a homemade
//! protocol.

#[derive(Debug)]
pub enum BridgeError {
    LibsignalNotConfigured,
}

pub fn status() -> Result<(), BridgeError> {
    Err(BridgeError::LibsignalNotConfigured)
}
