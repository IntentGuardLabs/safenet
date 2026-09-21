//! Sticky-primary RPC endpoint pool with per-endpoint circuit breakers.
//!
//! This is *not* a load balancer. One endpoint (the *active* one) serves every
//! request until it produces a classified endpoint failure (see
//! [`classify`](super::classify)). Isolated failures are retried on the same
//! endpoint with bounded, jittered exponential backoff; only after
//! `failure_threshold` consecutive failures does its circuit open and the next
//! healthy endpoint, in configured order, become active. An opened circuit is
//! probed again (half-open) after `cooldown`, but the pool never moves back to
//! a recovered higher-priority endpoint by itself mid-request: that only
//! happens in [`Pool::checkpoint`], which callers invoke between complete
//! block-processing units.
//!
//! Errors returned from here never contain endpoint URLs: transport errors can
//! embed credential-bearing URLs, so they are replaced by messages naming only
//! the configured endpoint name.

use super::classify::{Outcome, Reason, classify_error, classify_response};
use crate::metrics::{self, RpcRequestResult};
use alloy::{
    primitives::{B256, keccak256},
    rpc::json_rpc::{Id, Request, RequestPacket, ResponsePacket},
    transports::{BoxTransport, RpcError, TransportErrorKind, TransportFut, TransportResult},
};
use rand::Rng as _;
use std::{
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
use tower::Service;

/// Failover and circuit breaker settings.
#[derive(Clone, Copy, Debug)]
pub struct PoolConfig {
    pub request_timeout: Duration,
    pub failure_threshold: u32,
    pub cooldown: Duration,
    /// First retry delay; doubles per consecutive failure.
    pub backoff_base: Duration,
    /// Upper bound of the retry delay (before jitter).
    pub backoff_max: Duration,
}

impl PoolConfig {
    pub fn new(request_timeout: Duration, failure_threshold: u32, cooldown: Duration) -> Self {
        Self {
            request_timeout,
            failure_threshold,
            cooldown,
            backoff_base: Duration::from_millis(100),
            backoff_max: Duration::from_secs(2),
        }
    }

    fn backoff(&self, failures: u32) -> Duration {
        let exponent = failures.saturating_sub(1).min(16);
        let delay = self
            .backoff_base
            .saturating_mul(1 << exponent)
            .min(self.backoff_max);
        // Jitter in [delay/2, delay] to avoid synchronized retries.
        let half = delay / 2;
        half + half.mul_f64(rand::thread_rng().gen_range(0.0..=1.0))
    }
}

/// Circuit state of one endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Circuit {
    Healthy,
    /// The cooldown elapsed; the next request is a probe.
    HalfOpen,
    /// Not used until the cooldown elapses.
    Open,
}

impl Circuit {
    fn gauge(self) -> f64 {
        match self {
            Self::Healthy => 0.0,
            Self::HalfOpen => 1.0,
            Self::Open => 2.0,
        }
    }
}

/// A snapshot of one endpoint's health.
#[derive(Clone, Debug)]
pub struct EndpointStatus {
    pub name: Arc<str>,
    pub active: bool,
    pub circuit: Circuit,
    pub consecutive_failures: u32,
    pub last_success: Option<Instant>,
    pub open_until: Option<Instant>,
    /// The last head block (number, hash) observed from this endpoint.
    pub head: Option<(u64, B256)>,
}

struct Health {
    /// Whether the endpoint has been confirmed to be on the expected chain.
    /// Unvalidated endpoints (unreachable at startup) are never used, for
    /// failover or verification, until a probe validates them.
    validated: bool,
    /// Permanently excluded: it turned out to be on a different chain.
    rejected: bool,
    consecutive_failures: u32,
    last_success: Option<Instant>,
    circuit: Circuit,
    open_until: Option<Instant>,
    head: Option<(u64, B256)>,
}

struct State {
    active: usize,
    /// Incremented whenever the active endpoint changes.
    epoch: u64,
    health: Vec<Health>,
}

struct Endpoint {
    name: Arc<str>,
    transport: BoxTransport,
}

/// Whether a circuit may be used right now.
fn usable(health: &Health) -> bool {
    health.validated && health.circuit != Circuit::Open
}

struct Inner {
    /// The chain ID and genesis hash every endpoint must have, when known.
    expected: Option<(u64, B256)>,
    config: PoolConfig,
    endpoints: Vec<Endpoint>,
    state: Mutex<State>,
}

/// A sticky-primary failover pool over a fixed, ordered list of endpoints.
#[derive(Clone)]
pub struct Pool {
    inner: Arc<Inner>,
}

enum Attempt {
    Done(TransportResult<ResponsePacket>),
    /// A retryable failure; `switched` when the circuit opened and another
    /// endpoint became active (so no backoff is needed before the next try).
    Retry {
        error: Reason,
        switched: bool,
        failures: u32,
    },
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Endpoint names only.
        f.debug_struct("Pool")
            .field("active", &self.active_name())
            .finish()
    }
}

impl Pool {
    /// Creates a pool over `endpoints`, in priority order. The first is the
    /// initial primary.
    pub fn new(config: PoolConfig, endpoints: Vec<(Arc<str>, BoxTransport)>) -> Self {
        let validated = vec![true; endpoints.len()];
        Self::with_validation(config, endpoints, validated, None)
    }

    /// Like [`Pool::new`], but `validated[i]` says whether endpoint `i` was
    /// confirmed at startup. Unvalidated ones stay out of rotation until
    /// [`Pool::checkpoint`] validates them against `expected` (chain ID and
    /// genesis hash). At least one endpoint must be validated.
    pub fn with_validation(
        config: PoolConfig,
        endpoints: Vec<(Arc<str>, BoxTransport)>,
        validated: Vec<bool>,
        expected: Option<(u64, B256)>,
    ) -> Self {
        assert!(!endpoints.is_empty(), "a pool needs at least one endpoint");
        let active = validated
            .iter()
            .position(|v| *v)
            .expect("a pool needs at least one validated endpoint");
        let now = Instant::now();
        let health = validated
            .iter()
            .map(|&validated| Health {
                validated,
                rejected: false,
                consecutive_failures: 0,
                last_success: None,
                circuit: if validated {
                    Circuit::Healthy
                } else {
                    Circuit::Open
                },
                open_until: (!validated).then_some(now + config.cooldown),
                head: None,
            })
            .collect();
        let pool = Self {
            inner: Arc::new(Inner {
                expected,
                config,
                endpoints: endpoints
                    .into_iter()
                    .map(|(name, transport)| Endpoint { name, transport })
                    .collect(),
                state: Mutex::new(State {
                    active,
                    epoch: 0,
                    health,
                }),
            }),
        };
        pool.inner.sync_metrics(&pool.inner.lock());
        pool
    }

    /// The transport that sends every request to the active endpoint, failing
    /// over per the circuit breaker rules.
    pub fn transport(&self) -> PoolTransport {
        PoolTransport {
            inner: self.inner.clone(),
        }
    }

    /// The name of the currently active endpoint.
    pub fn active_name(&self) -> Arc<str> {
        let state = self.inner.lock();
        self.inner.endpoints[state.active].name.clone()
    }

    /// A counter that changes whenever the active endpoint changes.
    pub fn epoch(&self) -> u64 {
        self.inner.lock().epoch
    }

    /// Health of every endpoint, in configured order.
    pub fn status(&self) -> Vec<EndpointStatus> {
        let mut state = self.inner.lock();
        self.inner.refresh(&mut state);
        (0..self.inner.endpoints.len())
            .map(|i| {
                let h = &state.health[i];
                EndpointStatus {
                    name: self.inner.endpoints[i].name.clone(),
                    active: state.active == i,
                    circuit: h.circuit,
                    consecutive_failures: h.consecutive_failures,
                    last_success: h.last_success,
                    open_until: h.open_until,
                    head: h.head,
                }
            })
            .collect()
    }

    /// Whether at least one endpoint may currently be used.
    pub fn any_usable(&self) -> bool {
        let mut state = self.inner.lock();
        self.inner.refresh(&mut state);
        state.health.iter().any(usable)
    }

    /// The highest head block observed from any endpoint.
    pub fn max_observed_head(&self) -> Option<u64> {
        let state = self.inner.lock();
        state
            .health
            .iter()
            .filter_map(|h| h.head)
            .map(|(n, _)| n)
            .max()
    }

    /// Records the head block (number and hash) last seen from the active
    /// endpoint.
    pub fn observe_head(&self, number: u64, hash: B256) {
        let mut state = self.inner.lock();
        let active = state.active;
        state.health[active].head = Some((number, hash));
        metrics::rpc_endpoint_head(&self.inner.endpoints[active].name).set(number as f64);
    }

    /// Counts a failure the *caller* attributed to the active endpoint (for
    /// example a block it cannot serve). Opens the circuit at the threshold.
    pub fn report_failure(&self, reason: Reason) {
        let active = self.inner.lock().active;
        self.inner.record_failure(active, reason, false);
    }

    /// Immediately opens the active endpoint's circuit (an integrity failure
    /// with an established canonical result) and fails over.
    pub fn quarantine_active(&self, reason: Reason) {
        let active = self.inner.lock().active;
        self.inner.record_failure(active, reason, true);
    }

    /// The first usable endpoint other than the active one, for a one-off
    /// integrity verification (not load balancing).
    pub fn secondary(&self) -> Option<SecondaryTransport> {
        let mut state = self.inner.lock();
        self.inner.refresh(&mut state);
        let index = (0..self.inner.endpoints.len())
            .find(|&i| i != state.active && usable(&state.health[i]))?;
        Some(SecondaryTransport {
            inner: self.inner.clone(),
            index,
            name: self.inner.endpoints[index].name.clone(),
        })
    }

    /// Called between complete block-processing units: if a higher-priority
    /// endpoint than the active one is usable again, probe it and, when the
    /// probe succeeds, make it the primary again.
    pub async fn checkpoint(&self) {
        self.validate_pending().await;
        let candidate = {
            let mut state = self.inner.lock();
            self.inner.refresh(&mut state);
            (0..state.active).find(|&i| usable(&state.health[i]))
        };
        let Some(index) = candidate else { return };
        let probe = Request::new("eth_blockNumber", Id::Number(u64::MAX), ()).serialize();
        let Ok(probe) = probe else { return };
        if let Attempt::Done(Ok(_)) = self
            .inner
            .attempt(index, &RequestPacket::Single(probe))
            .await
        {
            let mut state = self.inner.lock();
            if index < state.active {
                let from = state.active;
                self.inner.switch(&mut state, from, index);
                tracing::info!(
                    endpoint = &*self.inner.endpoints[index].name,
                    "restored higher-priority RPC endpoint as primary"
                );
            }
        }
    }
}

impl Pool {
    /// Probes endpoints that were unreachable at startup (once their cooldown
    /// allows) and admits them to the rotation only if they report the expected
    /// chain ID and genesis hash. One that is on a different chain is excluded
    /// for good.
    async fn validate_pending(&self) {
        let Some((chain_id, genesis)) = self.inner.expected else {
            return;
        };
        let pending: Vec<usize> = {
            let mut state = self.inner.lock();
            self.inner.refresh(&mut state);
            (0..self.inner.endpoints.len())
                .filter(|&i| {
                    let h = &state.health[i];
                    !h.validated && !h.rejected && h.circuit != Circuit::Open
                })
                .collect()
        };
        for index in pending {
            let endpoint = &self.inner.endpoints[index];
            let result =
                super::validate::probe(&endpoint.transport, self.inner.config.request_timeout, 1)
                    .await;
            let mut state = self.inner.lock();
            let h = &mut state.health[index];
            match result {
                Ok((chain, hash)) if chain == chain_id && hash == genesis => {
                    h.validated = true;
                    h.circuit = Circuit::Healthy;
                    h.open_until = None;
                    tracing::info!(
                        endpoint = &*endpoint.name,
                        "RPC endpoint validated and admitted"
                    );
                }
                Ok(_) => {
                    h.rejected = true;
                    h.circuit = Circuit::Open;
                    h.open_until = None; // never retried
                    tracing::error!(
                        endpoint = &*endpoint.name,
                        "RPC endpoint is on a different chain than the others; excluded permanently"
                    );
                }
                Err(_) => {
                    h.circuit = Circuit::Open;
                    h.open_until = Some(Instant::now() + self.inner.config.cooldown);
                }
            }
            self.inner.sync_metrics(&state);
        }
    }
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        // Nothing here can panic while holding the lock, but do not propagate
        // a poisoned lock into every RPC call if it ever does.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Moves `Open` circuits whose cooldown elapsed to `HalfOpen`.
    fn refresh(&self, state: &mut State) {
        let now = Instant::now();
        for (i, h) in state.health.iter_mut().enumerate() {
            if h.circuit == Circuit::Open && h.open_until.is_some_and(|t| now >= t) {
                h.circuit = Circuit::HalfOpen;
                metrics::rpc_circuit_state(&self.endpoints[i].name).set(h.circuit.gauge());
            }
        }
    }

    fn sync_metrics(&self, state: &State) {
        for (i, endpoint) in self.endpoints.iter().enumerate() {
            let h = &state.health[i];
            metrics::rpc_circuit_state(&endpoint.name).set(h.circuit.gauge());
            metrics::rpc_consecutive_failures(&endpoint.name).set(h.consecutive_failures as f64);
            metrics::rpc_active_endpoint(&endpoint.name).set(if state.active == i {
                1.0
            } else {
                0.0
            });
        }
    }

    fn switch(&self, state: &mut State, from: usize, to: usize) {
        state.active = to;
        state.epoch += 1;
        metrics::rpc_failovers_total(&self.endpoints[from].name, &self.endpoints[to].name)
            .increment(1);
        tracing::warn!(
            from = &*self.endpoints[from].name,
            to = &*self.endpoints[to].name,
            "active RPC endpoint changed"
        );
        self.sync_metrics(state);
    }

    /// The index to send the next request to: the active endpoint while its
    /// circuit allows it, otherwise the first usable endpoint in order.
    fn select(&self) -> Option<usize> {
        let mut state = self.lock();
        self.refresh(&mut state);
        let active = state.active;
        if usable(&state.health[active]) {
            return Some(active);
        }
        let next = (0..self.endpoints.len()).find(|&i| usable(&state.health[i]))?;
        self.switch(&mut state, active, next);
        Some(next)
    }

    fn record_success(&self, index: usize) {
        let mut state = self.lock();
        let h = &mut state.health[index];
        h.consecutive_failures = 0;
        h.circuit = Circuit::Healthy;
        h.open_until = None;
        h.last_success = Some(Instant::now());
        self.sync_metrics(&state);
    }

    /// Returns `(switched, consecutive_failures)`.
    fn record_failure(&self, index: usize, reason: Reason, force_open: bool) -> (bool, u32) {
        let mut state = self.lock();
        let threshold = self.config.failure_threshold;
        let h = &mut state.health[index];
        h.consecutive_failures = h.consecutive_failures.saturating_add(1);
        let failures = h.consecutive_failures;
        let open = force_open || failures >= threshold || h.circuit == Circuit::HalfOpen;
        tracing::warn!(
            endpoint = &*self.endpoints[index].name,
            reason = reason.label(),
            failures,
            circuit_opened = open,
            "RPC endpoint failure"
        );
        let mut switched = false;
        if open {
            h.circuit = Circuit::Open;
            h.open_until = Some(Instant::now() + self.config.cooldown);
            if state.active == index {
                let next =
                    (0..self.endpoints.len()).find(|&i| i != index && usable(&state.health[i]));
                if let Some(next) = next {
                    self.switch(&mut state, index, next);
                    switched = true;
                }
            }
        }
        self.sync_metrics(&state);
        (switched, failures)
    }

    async fn attempt(&self, index: usize, request: &RequestPacket) -> Attempt {
        let endpoint = &self.endpoints[index];
        let method = request.method_names().next().unwrap_or("batch").to_owned();
        if method == "eth_sendRawTransaction" {
            // Attribute broadcasts by endpoint name and transaction hash, so
            // an ambiguous timeout followed by an identical rebroadcast is
            // traceable.
            if let Some(hash) = raw_transaction_hash(request) {
                tracing::info!(
                    endpoint = &*endpoint.name,
                    tx_hash = %hash,
                    "broadcasting signed transaction"
                );
            }
        }

        let mut transport = endpoint.transport.clone();
        let result =
            tokio::time::timeout(self.config.request_timeout, transport.call(request.clone()))
                .await;
        let (outcome, result) = match result {
            Err(_) => (
                Outcome::Retryable(Reason::Timeout),
                Err(TransportErrorKind::custom_str("request timed out")),
            ),
            Ok(Err(error)) => (classify_error(&error), Err(error)),
            Ok(Ok(response)) => (classify_response(request, &response), Ok(response)),
        };
        match outcome {
            Outcome::Success => {
                self.record_success(index);
                metrics::rpc_requests_total(&method, &endpoint.name, RpcRequestResult::Success)
                    .increment(1);
                Attempt::Done(result)
            }
            Outcome::Application => {
                // The endpoint answered coherently; the error is the caller's.
                self.record_success(index);
                metrics::rpc_requests_total(&method, &endpoint.name, RpcRequestResult::RpcError)
                    .increment(1);
                Attempt::Done(result.map_err(|error| self.sanitize(index, error)))
            }
            Outcome::Retryable(reason) => {
                metrics::rpc_requests_total(&method, &endpoint.name, RpcRequestResult::Failure)
                    .increment(1);
                let (switched, failures) = self.record_failure(index, reason, false);
                Attempt::Retry {
                    error: reason,
                    switched,
                    failures,
                }
            }
        }
    }

    /// Strips anything that could embed a URL from a returned error.
    fn sanitize(
        &self,
        index: usize,
        error: alloy::transports::TransportError,
    ) -> alloy::transports::TransportError {
        match error {
            RpcError::Transport(TransportErrorKind::Custom(_)) => {
                TransportErrorKind::custom_str(&format!(
                    "RPC endpoint {} transport error",
                    self.endpoints[index].name
                ))
            }
            other => other,
        }
    }

    async fn send(&self, request: RequestPacket) -> TransportResult<ResponsePacket> {
        let max_attempts = self
            .config
            .failure_threshold
            .saturating_mul(self.endpoints.len() as u32)
            .max(1);
        let mut last = None;
        for _ in 0..max_attempts {
            let Some(index) = self.select() else {
                break;
            };
            match self.attempt(index, &request).await {
                Attempt::Done(result) => return result,
                Attempt::Retry {
                    error,
                    switched,
                    failures,
                } => {
                    last = Some((self.endpoints[index].name.clone(), error));
                    if !switched {
                        tokio::time::sleep(self.config.backoff(failures)).await;
                    }
                }
            }
        }
        Err(TransportErrorKind::custom_str(&match last {
            Some((name, reason)) => format!(
                "RPC request failed: endpoint {name} ({}); no healthy endpoint left to try",
                reason.label()
            ),
            None => "no healthy RPC endpoint available".to_owned(),
        }))
    }
}

fn raw_transaction_hash(request: &RequestPacket) -> Option<B256> {
    let params = request.requests().first()?.params()?;
    let [raw]: [String; 1] = serde_json::from_str(params.get()).ok()?;
    Some(keccak256(alloy::hex::decode(raw).ok()?))
}

/// The pool as an `alloy` transport.
#[derive(Clone)]
pub struct PoolTransport {
    inner: Arc<Inner>,
}

impl Service<RequestPacket> for PoolTransport {
    type Response = ResponsePacket;
    type Error = alloy::transports::TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move { inner.send(request).await })
    }
}

/// A transport pinned to one specific endpoint, with a single attempt and no
/// failover. Used only for integrity verification against a second endpoint.
#[derive(Clone)]
pub struct SecondaryTransport {
    inner: Arc<Inner>,
    index: usize,
    name: Arc<str>,
}

impl SecondaryTransport {
    pub fn name(&self) -> &Arc<str> {
        &self.name
    }
}

impl Service<RequestPacket> for SecondaryTransport {
    type Response = ResponsePacket;
    type Error = alloy::transports::TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let inner = self.inner.clone();
        let (index, name) = (self.index, self.name.clone());
        Box::pin(async move {
            match inner.attempt(index, &request).await {
                Attempt::Done(result) => result,
                Attempt::Retry { error, .. } => Err(TransportErrorKind::custom_str(&format!(
                    "RPC endpoint {name} failed ({})",
                    error.label()
                ))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::fake::{Fake, Reply};
    use alloy::rpc::json_rpc::{Id, Request, ResponsePayload};
    use serde_json::json;

    const TIMEOUT: Duration = Duration::from_secs(10);
    const COOLDOWN: Duration = Duration::from_secs(30);

    fn pool_of(endpoints: &[(&str, &Fake)]) -> Pool {
        Pool::new(
            PoolConfig::new(TIMEOUT, 3, COOLDOWN),
            endpoints
                .iter()
                .map(|(name, fake)| (Arc::from(*name), fake.transport()))
                .collect(),
        )
    }

    fn ok() -> Fake {
        Fake::always(Reply::Ok(json!("0x1")))
    }

    async fn call(pool: &Pool, method: &'static str) -> TransportResult<ResponsePacket> {
        call_with(pool, method, json!([])).await
    }

    async fn call_with(
        pool: &Pool,
        method: &'static str,
        params: serde_json::Value,
    ) -> TransportResult<ResponsePacket> {
        let request = Request::new(method, Id::Number(1), params)
            .serialize()
            .unwrap();
        pool.transport().call(RequestPacket::Single(request)).await
    }

    fn is_error_response(response: &ResponsePacket, code: i64) -> bool {
        matches!(response.single_payload(),
            Some(ResponsePayload::Failure(e)) if e.code == code)
    }

    #[tokio::test(start_paused = true)]
    async fn uses_the_primary_while_healthy_and_never_round_robins() {
        let (a, b) = (ok(), ok());
        let pool = pool_of(&[("primary", &a), ("secondary", &b)]);
        for _ in 0..20 {
            call(&pool, "eth_blockNumber").await.unwrap();
        }
        assert_eq!(a.calls().len(), 20);
        assert!(b.calls().is_empty());
        assert_eq!(pool.epoch(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn one_failure_below_the_threshold_does_not_switch() {
        let (a, b) = (ok(), ok());
        a.script([Reply::Http(503)]);
        let pool = pool_of(&[("primary", &a), ("secondary", &b)]);

        call(&pool, "eth_blockNumber").await.unwrap();

        assert_eq!(a.calls().len(), 2); // failed once, retried on the primary
        assert!(b.calls().is_empty());
        assert_eq!(&*pool.active_name(), "primary");
        assert_eq!(pool.epoch(), 0);
        let status = pool.status();
        assert_eq!(status[0].circuit, Circuit::Healthy);
        assert_eq!(status[0].consecutive_failures, 0); // reset by the success
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_timeouts_open_the_circuit_and_switch() {
        let (a, b) = (Fake::always(Reply::Hang), ok());
        let pool = pool_of(&[("primary", &a), ("secondary", &b)]);

        call(&pool, "eth_blockNumber").await.unwrap();

        assert_eq!(a.calls().len(), 3); // exactly `failure_threshold`
        assert_eq!(b.calls().len(), 1);
        assert_eq!(&*pool.active_name(), "secondary");
        assert_eq!(pool.epoch(), 1);
        let status = pool.status();
        assert_eq!(status[0].circuit, Circuit::Open);
        assert!(status[1].active);
        // Subsequent requests stay on the new primary.
        call(&pool, "eth_blockNumber").await.unwrap();
        assert_eq!(a.calls().len(), 3);
        assert_eq!(b.calls().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn retryable_http_statuses_fail_over() {
        for status in [408, 429, 502, 503, 504] {
            let (a, b) = (Fake::always(Reply::Http(status)), ok());
            let pool = pool_of(&[("primary", &a), ("secondary", &b)]);
            call(&pool, "eth_blockNumber").await.unwrap();
            assert_eq!(&*pool.active_name(), "secondary", "{status}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn malformed_envelopes_and_id_mismatches_fail_over() {
        for reply in [Reply::Malformed, Reply::WrongId] {
            let (a, b) = (Fake::always(reply), ok());
            let pool = pool_of(&[("primary", &a), ("secondary", &b)]);
            call(&pool, "eth_blockNumber").await.unwrap();
            assert_eq!(&*pool.active_name(), "secondary");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn protocol_errors_are_returned_without_failover() {
        for code in [-32600, -32601, -32602, -32700] {
            let (a, b) = (Fake::always(Reply::Rpc(code, "bad")), ok());
            let pool = pool_of(&[("primary", &a), ("secondary", &b)]);
            let response = call(&pool, "eth_getLogs").await.unwrap();
            assert!(is_error_response(&response, code));
            assert_eq!(a.calls().len(), 1, "{code}: no retry either");
            assert!(b.calls().is_empty());
            assert_eq!(pool.epoch(), 0);
            assert_eq!(pool.status()[0].consecutive_failures, 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn transaction_errors_are_returned_without_failover() {
        for message in [
            "execution reverted",
            "insufficient funds for gas * price + value",
            "nonce too low",
            "nonce too high",
            "replacement transaction underpriced",
            "intrinsic gas too low",
            "max fee per gas less than block base fee",
            "max priority fee per gas higher than max fee per gas",
        ] {
            let (a, b) = (Fake::always(Reply::Rpc(-32000, message)), ok());
            let pool = pool_of(&[("primary", &a), ("secondary", &b)]);
            let response = call_with(&pool, "eth_sendRawTransaction", json!(["0x01"]))
                .await
                .unwrap();
            assert!(is_error_response(&response, -32000), "{message}");
            assert_eq!(a.calls().len(), 1);
            assert!(b.calls().is_empty(), "{message}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_vendor_codes_do_not_fail_over() {
        let (a, b) = (
            Fake::always(Reply::Rpc(-32050, "rate limit exceeded")),
            ok(),
        );
        let pool = pool_of(&[("primary", &a), ("secondary", &b)]);
        let response = call(&pool, "eth_getBlockByNumber").await.unwrap();
        assert!(is_error_response(&response, -32050));
        assert!(b.calls().is_empty());
        // ...but a reviewed code with a reviewed message does.
        let (a, b) = (
            Fake::always(Reply::Rpc(-32005, "request rate exceeded")),
            ok(),
        );
        let pool = pool_of(&[("primary", &a), ("secondary", &b)]);
        call(&pool, "eth_getBlockByNumber").await.unwrap();
        assert_eq!(&*pool.active_name(), "secondary");
    }

    #[tokio::test(start_paused = true)]
    async fn recovered_primary_is_only_restored_between_units() {
        let (a, b) = (Fake::always(Reply::Http(503)), ok());
        let pool = pool_of(&[("primary", &a), ("secondary", &b)]);
        call(&pool, "eth_blockNumber").await.unwrap();
        assert_eq!(&*pool.active_name(), "secondary");

        // The primary recovers and its cooldown elapses...
        a.set(|_, _| Reply::Ok(json!("0x1")));
        tokio::time::advance(COOLDOWN + Duration::from_secs(1)).await;
        assert_eq!(pool.status()[0].circuit, Circuit::HalfOpen);

        // ...but requests keep going to the secondary: no mid-unit move back.
        let before = a.calls().len();
        for _ in 0..5 {
            call(&pool, "eth_blockNumber").await.unwrap();
        }
        assert_eq!(a.calls().len(), before);
        assert_eq!(&*pool.active_name(), "secondary");

        // Only the checkpoint between units probes and restores it.
        pool.checkpoint().await;
        assert_eq!(&*pool.active_name(), "primary");
        assert_eq!(pool.status()[0].circuit, Circuit::Healthy);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_probe_reopens_the_circuit_and_keeps_the_secondary() {
        let (a, b) = (Fake::always(Reply::Http(503)), ok());
        let pool = pool_of(&[("primary", &a), ("secondary", &b)]);
        call(&pool, "eth_blockNumber").await.unwrap();
        tokio::time::advance(COOLDOWN + Duration::from_secs(1)).await;

        pool.checkpoint().await;

        assert_eq!(&*pool.active_name(), "secondary");
        assert_eq!(pool.status()[0].circuit, Circuit::Open);
    }

    #[tokio::test(start_paused = true)]
    async fn no_healthy_endpoint_is_an_error_not_a_hang() {
        let (a, b) = (
            Fake::always(Reply::Http(503)),
            Fake::always(Reply::Http(503)),
        );
        let pool = pool_of(&[("primary", &a), ("secondary", &b)]);
        assert!(call(&pool, "eth_blockNumber").await.is_err());
        assert!(!pool.any_usable());
        assert!(call(&pool, "eth_blockNumber").await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn ambiguous_broadcast_timeout_rebroadcasts_identical_bytes() {
        let (a, b) = (Fake::always(Reply::Hang), ok());
        let pool = pool_of(&[("primary", &a), ("secondary", &b)]);
        let raw = json!(["0x02f86a0102030405"]);

        call_with(&pool, "eth_sendRawTransaction", raw.clone())
            .await
            .unwrap();

        // Every attempt, on every endpoint, carried the same signed bytes.
        let all: Vec<_> = a.calls().into_iter().chain(b.calls()).collect();
        assert_eq!(all.len(), 4);
        assert!(
            all.iter()
                .all(|c| c.method == "eth_sendRawTransaction" && c.params == raw)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn returned_errors_never_contain_credentials() {
        let (a, b) = (
            Fake::always(Reply::LeakyTransportError),
            Fake::always(Reply::LeakyTransportError),
        );
        let pool = pool_of(&[("primary", &a), ("secondary", &b)]);
        let err = call(&pool, "eth_blockNumber").await.unwrap_err();
        let text = format!("{err} {err:?}");
        assert!(text.contains("primary") || text.contains("secondary"));
        for secret in ["hunter2", "SECRETKEY", "rpc.example", "https://"] {
            assert!(!text.contains(secret), "{secret} leaked in {text}");
        }
    }

    #[test]
    fn backoff_is_bounded_jittered_and_grows() {
        let config = PoolConfig::new(TIMEOUT, 3, COOLDOWN);
        for failures in 1..40 {
            let d = config.backoff(failures);
            assert!(d <= config.backoff_max);
            assert!(d >= config.backoff_base / 2);
        }
        assert!(config.backoff(1) <= config.backoff_base);
        assert!(config.backoff(6) > config.backoff_base);
    }

    #[tokio::test(start_paused = true)]
    async fn quarantine_switches_immediately() {
        let (a, b) = (ok(), ok());
        let pool = pool_of(&[("primary", &a), ("secondary", &b)]);
        pool.quarantine_active(Reason::InconsistentLogs);
        assert_eq!(&*pool.active_name(), "secondary");
        assert_eq!(pool.status()[0].circuit, Circuit::Open);
        call(&pool, "eth_blockNumber").await.unwrap();
        assert!(a.calls().is_empty());
    }
}
