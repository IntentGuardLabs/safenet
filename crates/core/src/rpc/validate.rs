//! Validation probe for an endpoint: the chain ID it reports and its genesis
//! block hash. Used at startup and, for endpoints that could not be reached
//! then, when the pool later brings them into rotation.

use alloy::{
    eips::BlockNumberOrTag,
    network::AnyNetwork,
    primitives::B256,
    providers::{Provider as _, RootProvider},
    rpc::client::ClientBuilder,
    transports::{BoxTransport, TransportError},
};
use std::{future::Future, time::Duration};

use super::classify::{Outcome, classify_error};

/// Why a probe failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeError {
    /// Rate limit, timeout, connection failure, ...: worth trying again later.
    Transient(&'static str),
    /// A definitive answer that is unusable (invalid response, no genesis).
    Failed(&'static str),
}

/// Runs `request`, retrying transient failures up to `attempts` times with
/// exponential backoff. Error text is never kept: it can embed the URL.
async fn retrying<T, F, Fut>(
    timeout: Duration,
    attempts: u32,
    mut request: F,
) -> Result<T, ProbeError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, TransportError>>,
{
    let mut delay = Duration::from_millis(500);
    for attempt in 1..=attempts {
        let error = match tokio::time::timeout(timeout, request()).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(error)) if matches!(classify_error(&error), Outcome::Retryable(_)) => {
                ProbeError::Transient(
                    "request failed transiently (rate limit, timeout or connection error)",
                )
            }
            Ok(Err(_)) => ProbeError::Failed("request failed or returned an invalid response"),
            Err(_) => ProbeError::Transient("timed out"),
        };
        if matches!(error, ProbeError::Failed(_)) || attempt == attempts {
            return Err(error);
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(8));
    }
    Err(ProbeError::Transient("no attempts"))
}

/// Asks the endpoint behind `transport` for its chain ID and genesis hash.
pub async fn probe(
    transport: &BoxTransport,
    timeout: Duration,
    attempts: u32,
) -> Result<(u64, B256), ProbeError> {
    let raw = RootProvider::<AnyNetwork>::new(
        ClientBuilder::default().transport(transport.clone(), false),
    );
    let chain = retrying(timeout, attempts, || raw.get_chain_id()).await?;
    let genesis = retrying(timeout, attempts, || {
        std::future::IntoFuture::into_future(raw.get_block_by_number(BlockNumberOrTag::Number(0)))
    })
    .await?
    .ok_or(ProbeError::Failed("did not return the genesis block"))?;
    Ok((chain, genesis.header.hash))
}
