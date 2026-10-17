//! `ubusd` — pure-Rust reimplementation of OpenWrt's `ubusd` broker.
//!
//! Exposed as both lib and bin so a host process can run the broker
//! standalone (the `ubusd` bin) or embed it in-process by driving
//! [`broker::Broker::poll_once`] from the host's event loop without
//! spawning a separate `ubusd`.

pub mod acl;
pub mod broker;
mod net;
pub mod peer;
#[cfg(target_os = "linux")]
mod poller;
pub mod registry;
pub mod reply;
pub mod routing;

#[cfg(feature = "testing")]
pub use broker::WriteGovernor;
pub use broker::{Broker, BrokerError, Config};
