//! Shared Ethereum provider construction used by Safenet services.

use crate::{
    rpc::{self, Pool, PoolConfig},
    utils::Json,
};
use alloy::{
    network::AnyNetwork,
    primitives::{B256, U64},
    providers::{Provider as AlloyProvider, ProviderCall, RootProvider},
    rpc::{
        client::{ClientBuilder, NoParams},
        json_rpc::{RequestPacket, ResponsePacket},
    },
    transports::{BoxTransport, TransportError, TransportFut},
};
#[cfg(any(test, feature = "test-util"))]
use alloy::{providers::ProviderBuilder, transports::mock::Asserter};
use std::{
    fmt::{self, Debug, Formatter},
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tower::{Layer, Service};

#[derive(Clone, Copy, Debug)]
struct ObservabilityLayer;

impl Layer<BoxTransport> for ObservabilityLayer {
    type Service = ObservabilityTransport;

    fn layer(&self, inner: BoxTransport) -> Self::Service {
        ObservabilityTransport { inner }
    }
}

#[derive(Clone, Debug)]
struct ObservabilityTransport {
    inner: BoxTransport,
}

struct ResponseJson<'a>(&'a ResponsePacket);

impl<'a> Debug for ResponseJson<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Work around the fact that `ResponsePacket` does not implement
        // `serde::Serialize` and implement `Debug` for it directly forwarding
        // the actual writing to the `Json` formatter implementation.
        match self.0 {
            ResponsePacket::Single(response) => write!(f, "{}", Json(response)),
            ResponsePacket::Batch(responses) => write!(f, "{}", Json(responses)),
        }
    }
}

impl Service<RequestPacket> for ObservabilityTransport {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request_packet: RequestPacket) -> Self::Future {
        // Request counters are recorded per attempt, by endpoint name, in the
        // [`Pool`]; this layer only traces.
        let mut inner = self.inner.clone();
        Box::pin(async move {
            tracing::trace!(
                request = %Json(&request_packet),
                "sending JSON-RPC request"
            );
            let response_packet = inner.call(request_packet).await;
            tracing::trace!(
                response = ?response_packet.as_ref().map(ResponseJson),
                "received JSON-RPC response"
            );
            response_packet
        })
    }
}

/// An error connecting to, or validating, the configured RPC endpoints.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error(transparent)]
    Config(#[from] rpc::ConfigError),
    #[error("failed to build HTTP client for RPC endpoint {0:?}")]
    Client(String),
    #[error("RPC endpoint {endpoint:?} could not be validated at startup: {reason}")]
    Unreachable {
        endpoint: String,
        reason: &'static str,
    },
    #[error("RPC endpoint {endpoint:?} reports chain ID {actual}, expected {expected}")]
    ChainId {
        endpoint: String,
        expected: u64,
        actual: u64,
    },
    #[error(
        "RPC endpoints {first:?} and {second:?} report different genesis blocks: they are on different chains"
    )]
    Genesis { first: String, second: String },
}

/// The standard [`alloy`] provider used by Safenet services.
///
/// Requests go through a sticky-primary failover [`Pool`] (a single endpoint
/// for the legacy `rpc = "<url>"` configuration).
#[derive(Clone, Debug)]
pub struct Provider {
    root: RootProvider<AnyNetwork>,
    chain_id: u64,
    pool: Option<Pool>,
}

impl Provider {
    /// Connects to a single `url` (the deprecated single-endpoint
    /// configuration). The endpoint is named `default`.
    pub async fn connect(url: &url::Url) -> Result<Self, ConnectError> {
        let endpoints = vec![rpc::Endpoint {
            name: Arc::from("default"),
            url: rpc::SecretUrl::new(url.clone()),
        }];
        let config = PoolConfig::new(Duration::from_secs(10), 3, Duration::from_secs(30));
        Self::connect_endpoints(config, None, endpoints).await
    }

    /// Connects to the configured endpoints (already loaded from their secret
    /// files), validating every one of them.
    pub async fn connect_rpc(
        config: &rpc::Config,
        endpoints: Vec<rpc::Endpoint>,
    ) -> Result<Self, ConnectError> {
        let pool = PoolConfig::new(
            config.request_timeout,
            config.failure_threshold,
            config.cooldown,
        );
        Self::connect_endpoints(pool, Some(config.expected_chain_id), endpoints).await
    }

    async fn connect_endpoints(
        config: PoolConfig,
        expected_chain_id: Option<u64>,
        endpoints: Vec<rpc::Endpoint>,
    ) -> Result<Self, ConnectError> {
        let mut transports = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let client = alloy::transports::http::reqwest::Client::builder()
                .timeout(config.request_timeout)
                .build()
                .map_err(|_| ConnectError::Client(endpoint.name.to_string()))?;
            let transport = rpc::http::HttpTransport::new(client, endpoint.url);
            transports.push((endpoint.name, BoxTransport::new(transport)));
        }
        Self::from_transports(config, expected_chain_id, transports).await
    }

    /// Builds a provider over already-connected `transports`, in priority
    /// order, after validating every one: each must report
    /// `expected_chain_id` (when given) and all must share one genesis hash.
    pub async fn from_transports(
        config: PoolConfig,
        expected_chain_id: Option<u64>,
        transports: Vec<(Arc<str>, BoxTransport)>,
    ) -> Result<Self, ConnectError> {
        // Validate each endpoint directly (not through the pool), so a wrong
        // endpoint is named and rejects the whole setup. One that is merely
        // unreachable (rate limited, down) does not block startup: it stays out
        // of rotation until the pool validates it later. At least one must
        // validate.
        let mut expected: Option<(u64, B256)> = None;
        let mut validated = Vec::with_capacity(transports.len());
        let mut first_failure = None;
        for (name, transport) in &transports {
            match rpc::validate::probe(transport, config.request_timeout, 5).await {
                Ok((actual, genesis)) => {
                    if let Some(expected_chain) = expected_chain_id
                        && actual != expected_chain
                    {
                        return Err(ConnectError::ChainId {
                            endpoint: name.to_string(),
                            expected: expected_chain,
                            actual,
                        });
                    }
                    match &expected {
                        Some((chain, hash)) if *chain != actual || *hash != genesis => {
                            return Err(ConnectError::Genesis {
                                first: transports[validated.iter().position(|v| *v).unwrap_or(0)]
                                    .0
                                    .to_string(),
                                second: name.to_string(),
                            });
                        }
                        Some(_) => {}
                        None => expected = Some((actual, genesis)),
                    }
                    validated.push(true);
                }
                Err(error) => {
                    let reason = match error {
                        rpc::validate::ProbeError::Transient(reason)
                        | rpc::validate::ProbeError::Failed(reason) => reason,
                    };
                    if matches!(error, rpc::validate::ProbeError::Failed(_)) {
                        return Err(ConnectError::Unreachable {
                            endpoint: name.to_string(),
                            reason,
                        });
                    }
                    tracing::warn!(
                        endpoint = &**name,
                        reason,
                        "RPC endpoint unreachable at startup; it stays out of rotation until validated"
                    );
                    first_failure.get_or_insert((name.to_string(), reason));
                    validated.push(false);
                }
            }
        }
        let Some((chain_id, genesis)) = expected else {
            let (endpoint, reason) = first_failure.expect("at least one endpoint");
            return Err(ConnectError::Unreachable { endpoint, reason });
        };

        let pool = Pool::with_validation(config, transports, validated, Some((chain_id, genesis)));
        let client = ClientBuilder::default()
            .layer(ObservabilityLayer)
            .transport(BoxTransport::new(pool.transport()), false);
        Ok(Self {
            root: RootProvider::new(client),
            chain_id,
            pool: Some(pool),
        })
    }

    /// The failover pool, unless this is a mocked provider.
    pub fn pool(&self) -> Option<&Pool> {
        self.pool.as_ref()
    }

    /// A provider pinned to the first usable endpoint other than the active
    /// one, for a one-off integrity verification.
    pub fn secondary(&self) -> Option<(Arc<str>, RootProvider<AnyNetwork>)> {
        let secondary = self.pool.as_ref()?.secondary()?;
        let name = secondary.name().clone();
        let client = ClientBuilder::default().transport(BoxTransport::new(secondary), false);
        Some((name, RootProvider::new(client)))
    }

    /// Creates a mocked provider.
    #[cfg(any(test, feature = "test-util"))]
    pub fn mocked(asserter: &Asserter) -> Self {
        Self::mocked_with_chain(asserter, 0x5afe)
    }

    /// Creates a mocked provider for a specific chain.
    #[cfg(any(test, feature = "test-util"))]
    pub fn mocked_with_chain(asserter: &Asserter, chain_id: u64) -> Self {
        let root = ProviderBuilder::default().connect_mocked_client(asserter.clone());
        Self {
            root,
            chain_id,
            pool: None,
        }
    }

    /// Returns the chain ID read when this provider connected.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

impl AlloyProvider<AnyNetwork> for Provider {
    fn root(&self) -> &RootProvider<AnyNetwork> {
        &self.root
    }

    fn get_chain_id(&self) -> ProviderCall<NoParams, U64, u64> {
        ProviderCall::Ready(Some(Ok(self.chain_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::fake::{Fake, Reply};
    use alloy::{
        consensus,
        rpc::types::{Block, Header},
    };
    use serde_json::json;

    fn chain(chain_id: u64, genesis: u8) -> Fake {
        Fake::new(chain_handler(chain_id, genesis))
    }

    fn chain_handler(
        chain_id: u64,
        genesis: u8,
    ) -> impl Fn(&str, &serde_json::Value) -> Reply + Send + Sync + 'static {
        move |method, _| match method {
            "eth_chainId" => Reply::Ok(json!(format!("{chain_id:#x}"))),
            "eth_getBlockByNumber" => Reply::Ok(
                serde_json::to_value(Block::<alloy::rpc::types::Transaction>::empty(Header {
                    hash: B256::repeat_byte(genesis),
                    inner: consensus::Header::default(),
                    ..Default::default()
                }))
                .unwrap(),
            ),
            _ => Reply::Rpc(-32601, "method not found"),
        }
    }

    async fn connect(expected: u64, endpoints: &[(&str, &Fake)]) -> Result<Provider, ConnectError> {
        Provider::from_transports(
            PoolConfig::new(Duration::from_secs(10), 3, Duration::from_secs(30)),
            Some(expected),
            endpoints
                .iter()
                .map(|(name, fake)| (Arc::from(*name), fake.transport()))
                .collect(),
        )
        .await
    }

    #[tokio::test]
    async fn accepts_endpoints_on_the_same_chain() {
        let (a, b) = (chain(100, 1), chain(100, 1));
        let provider = connect(100, &[("primary", &a), ("secondary", &b)])
            .await
            .unwrap();
        assert_eq!(provider.chain_id(), 100);
        assert_eq!(&*provider.pool().unwrap().active_name(), "primary");
    }

    #[tokio::test]
    async fn rejects_an_endpoint_with_the_wrong_chain_id() {
        let (a, b) = (chain(100, 1), chain(1, 1));
        let err = connect(100, &[("primary", &a), ("secondary", &b)])
            .await
            .unwrap_err();
        assert!(
            matches!(err, ConnectError::ChainId { ref endpoint, expected: 100, actual: 1 }
            if endpoint == "secondary"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn rejects_endpoints_with_different_genesis_hashes() {
        let (a, b) = (chain(100, 1), chain(100, 2));
        let err = connect(100, &[("primary", &a), ("secondary", &b)])
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectError::Genesis { .. }), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn starts_with_a_reachable_endpoint_when_another_is_down() {
        let (a, b) = (chain(100, 1), Fake::always(Reply::LeakyTransportError));
        let provider = connect(100, &[("primary", &a), ("secondary", &b)])
            .await
            .unwrap();
        let pool = provider.pool().unwrap();
        assert_eq!(&*pool.active_name(), "primary");
        // The unreachable endpoint is out of rotation: no failover or
        // verification target until it validates.
        assert!(pool.secondary().is_none());
        assert!(provider.secondary().is_none());

        // And if the *first* endpoint is the one that is down, the reachable
        // one is the primary.
        let (a, b) = (Fake::always(Reply::Http(429)), chain(100, 1));
        let provider = connect(100, &[("primary", &a), ("secondary", &b)])
            .await
            .unwrap();
        assert_eq!(&*provider.pool().unwrap().active_name(), "secondary");
    }

    #[tokio::test(start_paused = true)]
    async fn fails_when_no_endpoint_can_be_validated_without_leaking() {
        let (a, b) = (
            Fake::always(Reply::LeakyTransportError),
            Fake::always(Reply::LeakyTransportError),
        );
        let err = connect(100, &[("primary", &a), ("secondary", &b)])
            .await
            .unwrap_err();
        let text = format!("{err} {err:?}");
        assert!(matches!(err, ConnectError::Unreachable { .. }));
        assert!(
            !text.contains("hunter2") && !text.contains("SECRETKEY"),
            "{text}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_endpoint_down_at_startup_is_validated_before_it_is_used() {
        let (a, b) = (chain(100, 1), Fake::always(Reply::Http(503)));
        let provider = connect(100, &[("primary", &a), ("secondary", &b)])
            .await
            .unwrap();
        let pool = provider.pool().unwrap();
        assert!(pool.secondary().is_none());

        // It comes back, and after the cooldown a checkpoint validates it.
        b.set(chain_handler(100, 1));
        pool.checkpoint().await; // still cooling down: not probed yet
        assert!(pool.secondary().is_none());
        tokio::time::advance(Duration::from_secs(31)).await;
        pool.checkpoint().await;
        assert_eq!(&*pool.secondary().unwrap().name().to_owned(), "secondary");
        assert_eq!(
            &*pool.active_name(),
            "primary",
            "admitting is not switching"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_endpoint_that_turns_out_to_be_on_another_chain_is_excluded_for_good() {
        let (a, b) = (chain(100, 1), Fake::always(Reply::Http(503)));
        let provider = connect(100, &[("primary", &a), ("secondary", &b)])
            .await
            .unwrap();
        let pool = provider.pool().unwrap();

        b.set(chain_handler(1, 9)); // reachable now, but a different chain
        tokio::time::advance(Duration::from_secs(31)).await;
        pool.checkpoint().await;
        assert!(pool.secondary().is_none());
        // Never probed or admitted again, however long we wait.
        b.set(chain_handler(100, 1));
        tokio::time::advance(Duration::from_secs(600)).await;
        pool.checkpoint().await;
        assert!(pool.secondary().is_none());
    }
}
