//! The use cases of `mcp-remote-gate`. The crate holds the request handler of the gateway and
//! the session with the upstream server, and talks to the outside world only through the
//! traits of [`ports`]: it opens no file, socket or process and reads no clock of its own.

pub mod ports;
