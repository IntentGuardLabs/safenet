//! Readiness: whether the service is safely participating, as opposed to merely
//! alive. Exposed as `GET /ready` (200 or 503 with a list of reason codes) on
//! its own listener, and as the `safenet_core_ready` gauge. It exposes no
//! configuration, endpoint or key information.

use crate::{metrics, rpc::Pool};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};

/// Readiness configuration (`[readiness]`).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Not ready when the processed block is more than this many blocks behind
    /// the highest observed chain head.
    pub max_lag: u64,
    /// Not ready after this many consecutive failed attempts to process the
    /// current block.
    pub retry_budget: u32,
    /// Where to serve `GET /ready`. Disabled when unset.
    pub address: Option<SocketAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_lag: 50,
            retry_budget: 20,
            address: None,
        }
    }
}

#[derive(Default)]
struct Flags {
    processed: Option<u64>,
    head: Option<u64>,
    disagreement: bool,
    reorg_exceeded: bool,
    persist_failed: bool,
    retries: u32,
}

struct Inner {
    config: Config,
    pool: Option<Pool>,
    flags: Mutex<Flags>,
}

/// Shared readiness state, updated by the driver.
#[derive(Clone)]
pub struct Readiness(Arc<Inner>);

impl Readiness {
    pub fn new(config: Config, pool: Option<Pool>) -> Self {
        Self(Arc::new(Inner {
            config,
            pool,
            flags: Mutex::default(),
        }))
    }

    fn flags(&self) -> std::sync::MutexGuard<'_, Flags> {
        self.0.flags.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A block was fully processed and its state persisted.
    pub fn processed(&self, block: u64) {
        let mut flags = self.flags();
        flags.processed = Some(block);
        flags.disagreement = false;
        flags.retries = 0;
    }

    /// The chain head as seen by the watcher (used when there is no pool).
    pub fn head(&self, head: u64) {
        self.flags().head = Some(head);
    }

    /// Processing the current block failed again.
    pub fn retry(&self, endpoints_disagree: bool) {
        let mut flags = self.flags();
        flags.retries = flags.retries.saturating_add(1);
        flags.disagreement |= endpoints_disagree;
    }

    pub fn reorg_exceeded(&self) {
        self.flags().reorg_exceeded = true;
    }

    pub fn persistence_failed(&self) {
        self.flags().persist_failed = true;
    }

    /// The reasons the service is not ready; empty when it is.
    pub fn reasons(&self) -> Vec<&'static str> {
        let flags = self.flags();
        let mut reasons = Vec::new();
        if self.0.pool.as_ref().is_some_and(|pool| !pool.any_usable()) {
            reasons.push("no_healthy_endpoint");
        }
        match flags.processed {
            None => reasons.push("starting"),
            Some(processed) => {
                let head = self
                    .0
                    .pool
                    .as_ref()
                    .and_then(Pool::max_observed_head)
                    .max(flags.head);
                if head.is_some_and(|head| head.saturating_sub(processed) > self.0.config.max_lag) {
                    reasons.push("lagging");
                }
            }
        }
        if flags.disagreement {
            reasons.push("endpoint_disagreement");
        }
        if flags.reorg_exceeded {
            reasons.push("reorg_exceeded");
        }
        if flags.persist_failed {
            reasons.push("persistence_failed");
        }
        if flags.retries > self.0.config.retry_budget {
            reasons.push("retry_budget_exhausted");
        }
        reasons
    }

    /// Refreshes the readiness gauge and returns whether the service is ready.
    pub fn refresh(&self) -> bool {
        let ready = self.reasons().is_empty();
        metrics::ready().set(if ready { 1.0 } else { 0.0 });
        ready
    }

    /// Serves `GET /ready` until the task is dropped.
    pub async fn serve(self, address: SocketAddr) -> std::io::Result<()> {
        let listener = TcpListener::bind(address).await?;
        tracing::info!(%address, "serving readiness endpoint");
        loop {
            let (mut stream, _) = listener.accept().await?;
            let readiness = self.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 512];
                let read =
                    tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer)).await;
                let Ok(Ok(read)) = read else { return };
                let request = String::from_utf8_lossy(&buffer[..read]);
                let (status, body) = if request.starts_with("GET /ready ") {
                    readiness.refresh();
                    match readiness.reasons() {
                        reasons if reasons.is_empty() => ("200 OK", "ready".to_owned()),
                        reasons => ("503 Service Unavailable", reasons.join(",")),
                    }
                } else {
                    ("404 Not Found", String::new())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_reasons() {
        let readiness = Readiness::new(Config::default(), None);
        assert_eq!(readiness.reasons(), ["starting"]);

        readiness.head(1000);
        readiness.processed(990);
        assert!(readiness.reasons().is_empty());

        readiness.processed(900); // 100 behind, max_lag 50
        assert_eq!(readiness.reasons(), ["lagging"]);
        readiness.processed(1000);

        readiness.retry(true);
        assert_eq!(readiness.reasons(), ["endpoint_disagreement"]);
        readiness.processed(1000); // a processed block clears it
        assert!(readiness.reasons().is_empty());

        for _ in 0..21 {
            readiness.retry(false);
        }
        assert_eq!(readiness.reasons(), ["retry_budget_exhausted"]);
        readiness.processed(1000);

        readiness.reorg_exceeded();
        readiness.persistence_failed();
        assert_eq!(
            readiness.reasons(),
            ["reorg_exceeded", "persistence_failed"]
        );
    }

    #[tokio::test]
    async fn serves_ready_and_not_ready() {
        let readiness = Readiness::new(Config::default(), None);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        tokio::spawn(readiness.clone().serve(address));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let get = |path: &'static str| async move {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream
                .write_all(format!("GET {path} HTTP/1.1\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        };
        assert!(get("/ready").await.starts_with("HTTP/1.1 503"));
        readiness.processed(1);
        let ok = get("/ready").await;
        assert!(ok.starts_with("HTTP/1.1 200") && ok.ends_with("ready"));
        assert!(get("/other").await.starts_with("HTTP/1.1 404"));
    }
}
