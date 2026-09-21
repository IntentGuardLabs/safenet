//! This crate's own Prometheus metrics.

use metrics::{Counter, Gauge};
use tokio_metrics::RuntimeMetricsReporterBuilder;

/// The result of a JSON-RPC request attempt against one endpoint, as recorded
/// by [`rpc_requests_total`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcRequestResult {
    /// The endpoint returned a successful JSON-RPC response.
    Success,
    /// The endpoint returned a JSON-RPC error caused by the request itself
    /// (not an endpoint failure).
    RpcError,
    /// An endpoint or transport failure that counts against its circuit.
    Failure,
}

impl RpcRequestResult {
    fn label(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::RpcError => "rpc_error",
            Self::Failure => "failure",
        }
    }
}

/// Number of JSON-RPC request attempts, by `method`, configured `endpoint`
/// name and `result`. Never labelled by URL.
pub fn rpc_requests_total(method: &str, endpoint: &str, result: RpcRequestResult) -> Counter {
    let result = result.label();
    metrics::counter!(
        description: "Number of JSON-RPC request attempts, by method, endpoint name and result.",
        "safenet_core_rpc_requests_total",
        "method" => method.to_owned(),
        "endpoint" => endpoint.to_owned(),
        "result" => result,
    )
}

/// Number of times the active RPC endpoint changed.
pub fn rpc_failovers_total(from: &str, to: &str) -> Counter {
    metrics::counter!(
        description: "Number of times the active RPC endpoint changed, by endpoint names.",
        "safenet_core_rpc_failovers_total",
        "from" => from.to_owned(),
        "to" => to.to_owned(),
    )
}

/// Circuit state per endpoint: 0 = healthy, 1 = half-open, 2 = open.
pub fn rpc_circuit_state(endpoint: &str) -> Gauge {
    metrics::gauge!(
        description: "RPC endpoint circuit state (0 healthy, 1 half-open, 2 open).",
        "safenet_core_rpc_circuit_state",
        "endpoint" => endpoint.to_owned(),
    )
}

/// Consecutive retryable failures per endpoint.
pub fn rpc_consecutive_failures(endpoint: &str) -> Gauge {
    metrics::gauge!(
        description: "Consecutive retryable failures of an RPC endpoint.",
        "safenet_core_rpc_consecutive_failures",
        "endpoint" => endpoint.to_owned(),
    )
}

/// Latest head block number observed from an endpoint.
pub fn rpc_endpoint_head(endpoint: &str) -> Gauge {
    metrics::gauge!(
        description: "Latest head block observed from an RPC endpoint.",
        "safenet_core_rpc_endpoint_head_block",
        "endpoint" => endpoint.to_owned(),
    )
}

/// 1 for the currently active endpoint, 0 for the others.
pub fn rpc_active_endpoint(endpoint: &str) -> Gauge {
    metrics::gauge!(
        description: "Whether an RPC endpoint is the currently active one (1) or not (0).",
        "safenet_core_rpc_active_endpoint",
        "endpoint" => endpoint.to_owned(),
    )
}

/// The highest chain head observed from any endpoint.
pub fn rpc_head_block() -> Gauge {
    metrics::gauge!(
        description: "Highest chain head block observed.",
        "safenet_core_head_block",
    )
}

/// Times endpoints disagreed about, or returned inconsistent, event logs.
pub fn log_integrity_disagreements_total() -> Counter {
    metrics::counter!(
        description: "Number of log integrity disagreements between RPC endpoints.",
        "safenet_core_log_integrity_disagreements_total",
    )
}

/// Times processing of a block was retried after a failure.
pub fn block_processing_retries_total() -> Counter {
    metrics::counter!(
        description: "Number of block processing retries.",
        "safenet_core_block_processing_retries_total",
    )
}

/// Chain head minus processed block.
pub fn processed_block_lag() -> Gauge {
    metrics::gauge!(
        description: "Highest observed chain head minus the last processed block.",
        "safenet_core_processed_block_lag",
    )
}

/// Unix timestamp (seconds) of the last successfully processed block.
pub fn last_processed_block_timestamp() -> Gauge {
    metrics::gauge!(
        description: "Unix time in seconds at which a block was last successfully processed.",
        "safenet_core_last_processed_block_timestamp_seconds",
    )
}

/// 1 when the service is ready (safely participating), else 0.
pub fn ready() -> Gauge {
    metrics::gauge!(
        description: "Whether the service considers itself ready (1) or not (0).",
        "safenet_core_ready",
    )
}

/// The point in the chain-processing lifecycle represented by the cursor
/// gauges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessingStatus {
    /// The update was received from the chain watcher.
    Seen,
    /// The update was successfully applied to the state machine.
    Processed,
}

impl ProcessingStatus {
    /// Returns all variants for the processing status.
    pub fn variants() -> impl Iterator<Item = Self> {
        [Self::Seen, Self::Processed].into_iter()
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Seen => "seen",
            Self::Processed => "processed",
        }
    }
}

/// The block-number component of the chain-processing cursor, by `status`.
pub fn block_number(status: ProcessingStatus) -> Gauge {
    let status = status.label();
    metrics::gauge!(
        description: "Block number by chain-processing status.",
        "safenet_core_block_number",
        "status" => status,
    )
}

/// Number of live blocks invalidated by chain reorgs.
pub fn uncled_blocks_total() -> Counter {
    metrics::counter!(
        description: "Number of live blocks invalidated by chain reorgs.",
        "safenet_core_uncled_blocks_total",
    )
}

/// Initializes core metrics.
pub fn initialize() {
    for status in ProcessingStatus::variants() {
        block_number(status).set(0.0);
    }
    uncled_blocks_total().absolute(0);

    // Spawn a background task to collect and report metrics on the underlying
    // Tokio runtime.
    tokio::spawn(RuntimeMetricsReporterBuilder::default().describe_and_run());
}
