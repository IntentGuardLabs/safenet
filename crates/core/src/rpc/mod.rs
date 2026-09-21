//! Multi-endpoint RPC access with sticky-primary failover.
//!
//! See [`pool`] for the failover semantics, [`classify`] for what counts as an
//! endpoint failure, and [`config`] for the `[rpc]` configuration.

pub mod classify;
pub mod config;
#[cfg(test)]
pub(crate) mod fake;
pub mod http;
pub mod pool;
pub mod validate;

pub use self::{
    classify::Reason,
    config::{Config, ConfigError, Endpoint, SecretUrl},
    pool::{Circuit, EndpointStatus, Pool, PoolConfig},
};
