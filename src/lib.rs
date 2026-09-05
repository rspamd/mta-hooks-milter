//! An independent, bounded milter v6 implementation using Tokio.
//!
//! [`protocol`] is the wire codec; [`session`] owns SMTP transaction state;
//! [`server`] runs asynchronous policies without blocking other connections.
//! [`hooks`] implements a deliberately limited MTA Hooks draft-01 client.
pub mod hooks;
pub mod http;
pub mod protocol;
pub mod server;
pub mod session;
