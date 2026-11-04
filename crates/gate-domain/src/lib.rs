//! The pure core of `mcp-remote-gate`: everything that decides whether a request may pass and
//! what it may carry. The crate uses `std` only and performs no I/O: no files, no sockets, no
//! processes, no clock and no randomness. Time and entropy arrive through arguments.

pub mod audit;
pub mod auth;
pub mod framing;
pub mod glob;
pub mod hash;
pub mod hostcheck;
pub mod json;
pub mod jsonrpc;
pub mod policy;
pub mod ratelimit;
pub mod sanitize;
