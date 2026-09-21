//! Classification of RPC failures into "the endpoint is unavailable or
//! untrustworthy" (fail over) and "the request or transaction is at fault"
//! (return to the caller; never hide by switching endpoints).
//!
//! The rules are deliberately conservative and explicit. Anything not
//! positively recognised as an endpoint failure is an application error. In
//! particular vendor-specific `-320xx` codes are never failover triggers by
//! code alone: they only are when the *message* matches a reviewed
//! infrastructure pattern below.

use alloy::{
    rpc::json_rpc::{ErrorPayload, Id, RequestPacket, ResponsePacket, ResponsePayload},
    transports::{RpcError, TransportError, TransportErrorKind},
};
use std::{collections::HashMap, io};

/// Why an endpoint request counted as an endpoint failure. A small, closed set
/// so it is safe to use as a metric label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    /// The request timed out.
    Timeout,
    /// DNS, TCP or TLS connection failure.
    Connect,
    /// Connection reset, unexpected EOF or truncated response.
    Truncated,
    /// HTTP 408, 429, 502, 503 or 504.
    HttpStatus,
    /// The HTTP response was not a well-formed JSON-RPC envelope.
    MalformedEnvelope,
    /// A response ID did not match a request ID.
    IdMismatch,
    /// A reviewed "endpoint overloaded / rate limited / unavailable" message.
    Unavailable,
    /// The endpoint lacks a block that another endpoint has, or is behind the
    /// persisted cursor.
    MissingBlock,
    /// The endpoint's block/parent hashes disagree with the canonical chain.
    InconsistentChain,
    /// The endpoint's logs are incomplete or disagree with another endpoint.
    InconsistentLogs,
}

impl Reason {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::Truncated => "truncated",
            Self::HttpStatus => "http_status",
            Self::MalformedEnvelope => "malformed_envelope",
            Self::IdMismatch => "id_mismatch",
            Self::Unavailable => "unavailable",
            Self::MissingBlock => "missing_block",
            Self::InconsistentChain => "inconsistent_chain",
            Self::InconsistentLogs => "inconsistent_logs",
        }
    }
}

/// The classification of one endpoint response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// A usable response.
    Success,
    /// A well-formed JSON-RPC error caused by the request, query or
    /// transaction. The endpoint is fine; the error goes to the caller.
    Application,
    /// An endpoint or transport failure: retry / fail over.
    Retryable(Reason),
}

/// Message fragments (lowercase) that identify an overloaded, rate limited or
/// unavailable endpoint. Reviewed list: extend deliberately, with a test.
const INFRASTRUCTURE_MESSAGES: &[&str] = &[
    "rate limit",
    "rate-limit",
    "request rate",
    "too many requests",
    "over capacity",
    "overloaded",
    "service unavailable",
    "temporarily unavailable",
    "no backend",
    "no healthy",
    "bad gateway",
    "gateway timeout",
    "upstream request timeout",
    "request timed out",
    "not synced",
    "still syncing",
    "missing trie node",
];

/// Message fragments (lowercase) that mark a query the caller built badly,
/// even if they also contain an infrastructure-looking word.
const QUERY_MESSAGES: &[&str] = &[
    "block range",
    "more than",
    "exceeds maximum",
    "exceed maximum",
    "limit exceeded: query",
];

/// Whether a JSON-RPC error means the *endpoint* is unavailable.
///
/// `method` is part of the decision: e.g. block-range messages on `eth_getLogs`
/// are a locally invalid query, and transaction rejections on
/// `eth_sendRawTransaction` are never endpoint failures.
pub fn classify_rpc_error(method: &str, error: &ErrorPayload) -> Outcome {
    match error.code {
        // Parse error, invalid request, method not found, invalid params:
        // the request is wrong.
        -32700 | -32600 | -32601 | -32602 => return Outcome::Application,
        _ => {}
    }
    let message = error.message.to_ascii_lowercase();
    if QUERY_MESSAGES.iter().any(|m| message.contains(m)) {
        return Outcome::Application;
    }
    // Transaction/EVM level rejections are deterministic: they must be handled
    // by the transaction queue whatever code they arrive with.
    if method == "eth_sendRawTransaction" || method == "eth_call" || method == "eth_estimateGas" {
        const APPLICATION: &[&str] = &[
            "revert",
            "insufficient funds",
            "nonce",
            "underpriced",
            "intrinsic gas",
            "fee cap",
            "max fee",
            "priority fee",
            "already known",
            "invalid sender",
            "invalid signature",
            "execution",
            "gas",
        ];
        if APPLICATION.iter().any(|m| message.contains(m)) {
            return Outcome::Application;
        }
    }
    // Reviewed codes: the generic server error, EIP-1474 limit exceeded /
    // resource unavailable, and JSON-RPC internal error, *and only* with a
    // reviewed infrastructure message. Every other `-320xx` is application.
    let reviewed_code = matches!(error.code, -32000 | -32002 | -32005 | -32603);
    if reviewed_code && INFRASTRUCTURE_MESSAGES.iter().any(|m| message.contains(m)) {
        return Outcome::Retryable(Reason::Unavailable);
    }
    Outcome::Application
}

/// Whether a JSON-RPC error means "this block is not available on this
/// endpoint" (uncled, not yet synced, or pruned). Not an endpoint failure on
/// its own: the indexer decides using a second endpoint.
pub fn is_block_unavailable(error: &ErrorPayload) -> bool {
    let message = error.message.to_ascii_lowercase();
    error.code == -32001
        || (error.code == -32000
            && ["unknown block", "header not found", "block not found"]
                .iter()
                .any(|m| message.contains(m)))
}

/// Classifies an HTTP status.
fn classify_status(status: u16) -> Outcome {
    match status {
        408 | 429 | 502 | 503 | 504 => Outcome::Retryable(Reason::HttpStatus),
        _ => Outcome::Application,
    }
}

/// Classifies a transport-level error. Error text is never inspected for
/// display: transport errors can embed the (credential-bearing) URL.
pub fn classify_error(error: &TransportError) -> Outcome {
    match error {
        RpcError::Transport(kind) => match kind {
            TransportErrorKind::HttpError(http) => classify_status(http.status),
            TransportErrorKind::MissingBatchResponse(_) => {
                Outcome::Retryable(Reason::MalformedEnvelope)
            }
            TransportErrorKind::BackendGone => Outcome::Retryable(Reason::Connect),
            TransportErrorKind::Custom(source) => classify_custom(source.as_ref()),
            TransportErrorKind::PubsubUnavailable | TransportErrorKind::NonRetryable(_) => {
                Outcome::Application
            }
            _ => Outcome::Application,
        },
        // The HTTP response was not a JSON-RPC envelope.
        RpcError::DeserError { .. } | RpcError::NullResp => {
            Outcome::Retryable(Reason::MalformedEnvelope)
        }
        // A JSON-RPC error carried as `Err`: classify the payload without a
        // method (used defensively; the pool sees errors inside responses).
        RpcError::ErrorResp(payload) => classify_rpc_error("", payload),
        RpcError::UnsupportedFeature(_) | RpcError::LocalUsageError(_) | RpcError::SerError(_) => {
            Outcome::Application
        }
    }
}

fn classify_custom(error: &(dyn std::error::Error + 'static)) -> Outcome {
    if let Some(error) = error.downcast_ref::<alloy::transports::http::reqwest::Error>() {
        if error.is_timeout() {
            return Outcome::Retryable(Reason::Timeout);
        }
        if error.is_connect() {
            return Outcome::Retryable(Reason::Connect);
        }
        if error.is_builder() {
            return Outcome::Application;
        }
        if error.is_body() || error.is_decode() {
            return Outcome::Retryable(Reason::Truncated);
        }
    }
    // Walk the source chain for IO errors (reset, EOF, ...).
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if let Some(io) = current.downcast_ref::<io::Error>() {
            return Outcome::Retryable(match io.kind() {
                io::ErrorKind::TimedOut => Reason::Timeout,
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotConnected => Reason::Connect,
                _ => Reason::Truncated,
            });
        }
        source = current.source();
    }
    // Any other failure to complete an HTTP exchange is a transport problem.
    Outcome::Retryable(Reason::Truncated)
}

/// Classifies a full response packet against the request that produced it:
/// checks response IDs first, then each JSON-RPC error payload by method.
pub fn classify_response(request: &RequestPacket, response: &ResponsePacket) -> Outcome {
    let methods: HashMap<&Id, &str> = request
        .requests()
        .iter()
        .map(|request| (request.id(), request.method()))
        .collect();
    let responses = response.responses();
    if responses.len() != methods.len() || responses.iter().any(|r| !methods.contains_key(&r.id)) {
        return Outcome::Retryable(Reason::IdMismatch);
    }
    let mut outcome = Outcome::Success;
    for response in responses {
        if let ResponsePayload::Failure(error) = &response.payload {
            match classify_rpc_error(methods[&response.id], error) {
                retryable @ Outcome::Retryable(_) => return retryable,
                _ => outcome = Outcome::Application,
            }
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::transports::HttpError;

    fn payload(code: i64, message: &str) -> ErrorPayload {
        ErrorPayload {
            code,
            message: message.to_owned().into(),
            data: None,
        }
    }

    fn http(status: u16) -> TransportError {
        RpcError::Transport(TransportErrorKind::HttpError(HttpError {
            status,
            body: String::new(),
        }))
    }

    #[test]
    fn retryable_http_statuses() {
        for status in [408, 429, 502, 503, 504] {
            assert!(matches!(
                classify_error(&http(status)),
                Outcome::Retryable(Reason::HttpStatus)
            ));
        }
        for status in [400, 401, 403, 404, 500] {
            assert_eq!(classify_error(&http(status)), Outcome::Application);
        }
    }

    #[test]
    fn protocol_errors_do_not_fail_over() {
        for code in [-32700, -32600, -32601, -32602] {
            // Even with an infrastructure-sounding message.
            let error = payload(code, "rate limit exceeded");
            assert_eq!(
                classify_rpc_error("eth_getLogs", &error),
                Outcome::Application,
                "{code}"
            );
        }
    }

    #[test]
    fn transaction_errors_do_not_fail_over() {
        for message in [
            "execution reverted: nope",
            "insufficient funds for gas * price + value",
            "nonce too low",
            "nonce too high",
            "replacement transaction underpriced",
            "intrinsic gas too low",
            "max fee per gas less than block base fee",
            "max priority fee per gas higher than max fee per gas",
            "already known",
            "invalid sender",
        ] {
            for code in [-32000, -32003, -32010] {
                assert_eq!(
                    classify_rpc_error("eth_sendRawTransaction", &payload(code, message)),
                    Outcome::Application,
                    "{code} {message}"
                );
            }
        }
    }

    #[test]
    fn unknown_vendor_codes_default_to_no_failover() {
        for code in [-32001, -32003, -32004, -32006, -32010, -32050, -32099] {
            assert_eq!(
                classify_rpc_error("eth_getBlockByNumber", &payload(code, "something odd")),
                Outcome::Application,
                "{code}"
            );
        }
        // A vendor code with an unreviewed message is still not a trigger.
        assert_eq!(
            classify_rpc_error("eth_getLogs", &payload(-32050, "rate limit exceeded")),
            Outcome::Application
        );
    }

    #[test]
    fn reviewed_infrastructure_messages_fail_over() {
        for (code, message) in [
            (-32005, "Project ID request rate exceeded"),
            (-32000, "Too many requests"),
            (-32603, "upstream request timeout"),
            (-32002, "service unavailable"),
            (-32000, "missing trie node abc"),
        ] {
            assert_eq!(
                classify_rpc_error("eth_getBlockByNumber", &payload(code, message)),
                Outcome::Retryable(Reason::Unavailable),
                "{message}"
            );
        }
    }

    #[test]
    fn invalid_queries_never_fail_over_on_get_logs() {
        for message in [
            "query returned more than 10000 results",
            "block range too large",
            "exceed maximum block range: 5000",
        ] {
            assert_eq!(
                classify_rpc_error("eth_getLogs", &payload(-32005, message)),
                Outcome::Application,
                "{message}"
            );
        }
    }

    #[test]
    fn block_unavailable_is_recognised_but_not_an_endpoint_failure() {
        let error = payload(-32000, "header not found");
        assert!(is_block_unavailable(&error));
        assert_eq!(
            classify_rpc_error("eth_getLogs", &error),
            Outcome::Application
        );
        assert!(is_block_unavailable(&payload(-32001, "resource not found")));
        assert!(!is_block_unavailable(&payload(-32000, "nonce too low")));
    }

    #[test]
    fn malformed_envelopes_fail_over() {
        let err = RpcError::deser_err(serde_json::from_str::<u8>("x").unwrap_err(), "x");
        assert_eq!(
            classify_error(&err),
            Outcome::Retryable(Reason::MalformedEnvelope)
        );
    }

    #[test]
    fn io_errors_are_transport_failures() {
        for (kind, reason) in [
            (io::ErrorKind::ConnectionReset, Reason::Truncated),
            (io::ErrorKind::UnexpectedEof, Reason::Truncated),
            (io::ErrorKind::TimedOut, Reason::Timeout),
            (io::ErrorKind::ConnectionRefused, Reason::Connect),
        ] {
            let err = TransportErrorKind::custom(io::Error::from(kind));
            assert_eq!(classify_error(&err), Outcome::Retryable(reason), "{kind:?}");
        }
    }
}
