//! The JSON-RPC HTTP transport used for real endpoints.
//!
//! `alloy`'s own HTTP transport wraps every request in a tracing span that
//! records the full URL, so at `debug`/`trace` log levels every line would
//! carry credential-bearing URLs. This transport does the same POST but never
//! puts the URL in a span, log or error: `reqwest` errors are stripped of it
//! and identified elsewhere by the configured endpoint name only.

use super::config::SecretUrl;
use alloy::{
    rpc::json_rpc::{RequestPacket, ResponsePacket},
    transports::{TransportError, TransportErrorKind, TransportFut, http::reqwest},
};
use std::task::{Context, Poll};
use tower::Service;

/// A JSON-RPC over HTTP(S) transport for one endpoint.
#[derive(Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
    url: SecretUrl,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("HttpTransport(<redacted>)")
    }
}

impl HttpTransport {
    pub fn new(client: reqwest::Client, url: SecretUrl) -> Self {
        Self { client, url }
    }
}

impl Service<RequestPacket> for HttpTransport {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let client = self.client.clone();
        let url = self.url.expose().clone();
        Box::pin(async move {
            let response = client
                .post(url)
                .json(&request)
                .headers(request.headers())
                .send()
                .await
                .map_err(|err| TransportErrorKind::custom(err.without_url()))?;
            let status = response.status();
            let body = response
                .bytes()
                .await
                .map_err(|err| TransportErrorKind::custom(err.without_url()))?;
            if !status.is_success() {
                return Err(TransportErrorKind::http_error(
                    status.as_u16(),
                    String::from_utf8_lossy(&body).into_owned(),
                ));
            }
            serde_json::from_slice(&body)
                .map_err(|err| TransportError::deser_err(err, String::from_utf8_lossy(&body)))
        })
    }
}
