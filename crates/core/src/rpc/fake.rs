//! A scripted transport for deterministic failover tests.

use alloy::{
    rpc::json_rpc::{RequestPacket, ResponsePacket},
    transports::{BoxTransport, TransportError, TransportErrorKind, TransportFut},
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tower::Service;

/// How a fake endpoint answers one request.
#[derive(Clone, Debug)]
pub enum Reply {
    /// A successful JSON-RPC `result`.
    Ok(Value),
    /// A JSON-RPC error response.
    Rpc(i64, &'static str),
    /// A non-2xx HTTP status.
    Http(u16),
    /// Never answers (times out).
    Hang,
    /// A transport error whose text embeds a credential-bearing URL.
    LeakyTransportError,
    /// A response with the wrong ID.
    WrongId,
    /// A body that is not a JSON-RPC envelope.
    Malformed,
}

type Handler = dyn Fn(&str, &Value) -> Reply + Send + Sync;

/// A recorded request.
#[derive(Clone, Debug)]
pub struct Call {
    pub method: String,
    pub params: Value,
}

/// A fake endpoint: a queue of one-off replies, then a handler.
#[derive(Clone)]
pub struct Fake {
    calls: Arc<Mutex<Vec<Call>>>,
    queue: Arc<Mutex<VecDeque<Reply>>>,
    handler: Arc<Mutex<Arc<Handler>>>,
}

impl Fake {
    /// Answers every request with `handler(method, params)`.
    pub fn new(handler: impl Fn(&str, &Value) -> Reply + Send + Sync + 'static) -> Self {
        Self {
            calls: Default::default(),
            queue: Default::default(),
            handler: Arc::new(Mutex::new(Arc::new(handler))),
        }
    }

    /// Answers every request with `reply`.
    pub fn always(reply: Reply) -> Self {
        Self::new(move |_, _| reply.clone())
    }

    /// Replaces the handler.
    pub fn set(&self, handler: impl Fn(&str, &Value) -> Reply + Send + Sync + 'static) {
        *self.handler.lock().unwrap() = Arc::new(handler);
    }

    /// Answers the next requests with `replies` before falling back to the
    /// handler.
    pub fn script(&self, replies: impl IntoIterator<Item = Reply>) {
        self.queue.lock().unwrap().extend(replies);
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    pub fn transport(&self) -> BoxTransport {
        BoxTransport::new(self.clone())
    }
}

impl Service<RequestPacket> for Fake {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let request = match &request {
            RequestPacket::Single(request) => request.clone(),
            RequestPacket::Batch(_) => panic!("fake endpoints do not support batches"),
        };
        let method = request.method().to_owned();
        let params: Value = request
            .params()
            .map(|p| serde_json::from_str(p.get()).unwrap())
            .unwrap_or(Value::Null);
        let id = serde_json::to_value(request.id()).unwrap();
        self.calls.lock().unwrap().push(Call {
            method: method.clone(),
            params: params.clone(),
        });
        let reply = self.queue.lock().unwrap().pop_front();
        let handler = self.handler.lock().unwrap().clone();
        Box::pin(async move {
            let reply = reply.unwrap_or_else(|| handler(&method, &params));
            let envelope = |id: Value, body: Value| {
                let mut envelope = json!({ "jsonrpc": "2.0", "id": id });
                envelope
                    .as_object_mut()
                    .unwrap()
                    .extend(body.as_object().unwrap().clone());
                serde_json::from_value::<ResponsePacket>(envelope)
                    .map_err(|err| TransportError::deser_err(err, "<fake>"))
            };
            match reply {
                Reply::Ok(result) => envelope(id, json!({ "result": result })),
                Reply::Rpc(code, message) => {
                    envelope(id, json!({ "error": { "code": code, "message": message } }))
                }
                Reply::Http(status) => Err(TransportErrorKind::http_error(status, String::new())),
                Reply::Hang => std::future::pending().await,
                Reply::LeakyTransportError => Err(TransportErrorKind::custom_str(
                    "error sending request for url (https://user:hunter2@rpc.example/v1/SECRETKEY)",
                )),
                Reply::WrongId => envelope(json!(999_999), json!({ "result": "0x1" })),
                Reply::Malformed => Err(TransportError::deser_err(
                    serde_json::from_str::<u8>("not json").unwrap_err(),
                    "<html>",
                )),
            }
        })
    }
}
