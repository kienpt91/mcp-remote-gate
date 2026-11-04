//! The adapters of `mcp-remote-gate`: they implement the ports of `gate-app` with real files,
//! sockets, processes and clocks, and read the configuration file.

pub mod config_file;
pub mod testutil;
pub mod toml;
pub mod system;
