//! The adapters of `mcp-remote-gate`: they implement the ports of `gate-app` with real files,
//! sockets, processes and clocks, and read the configuration file.

pub mod audit_file;
pub mod child;
pub mod config_file;
pub mod http;
pub mod httpclient;
pub mod system;
pub mod testutil;
pub mod toml;
