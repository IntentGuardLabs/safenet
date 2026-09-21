//! Live multi-endpoint tests against real Ethereum mainnet RPC endpoints.
//!
//! Ignored by default. Run with two URL *files* (they may contain credentials,
//! which is why they are files, never arguments or repo content):
//!
//!   SAFENET_LIVE_RPC_FILES=/path/primary-url,/path/secondary-url \
//!     cargo test -p safenet-core --test live_rpc -- --ignored --nocapture --test-threads=1
//!
//! Only read-only calls are made. Failover is exercised by wrapping a real
//! transport and failing it on demand, so no real endpoint is harmed.

use alloy::{
    primitives::{Address, address},
    providers::Provider as _,
    rpc::json_rpc::{RequestPacket, ResponsePacket},
    sol,
    transports::{BoxTransport, TransportError, TransportErrorKind, TransportFut, http::reqwest},
};
use safenet_core::{
    index::{
        BlockUpdate, Config as IndexConfig, Update, Watcher,
        blocks::{self, BlockTime},
        events,
    },
    provider::{ConnectError, Provider},
    rpc::{Circuit, PoolConfig, SecretUrl, http::HttpTransport},
    watcher_events,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tower::Service;

const WETH: Address = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");

sol! {
    #[derive(Debug, Eq, PartialEq)]
    contract Weth {
        event Deposit(address indexed dst, uint256 wad);
        event Withdrawal(address indexed src, uint256 wad);
    }
    // Emitted by Uniswap V2 pairs, never by WETH itself: the block bloom
    // usually contains both the WETH address and this topic, so the bloom
    // cannot rule logs out, yet the true answer is empty.
    #[derive(Debug, Eq, PartialEq)]
    contract Pair {
        event Sync(uint112 reserve0, uint112 reserve1);
    }
}
watcher_events!(Weth::WethEvents);
watcher_events!(Pair::PairEvents);

/// Captures tracing output so we can assert no credential ever reaches a log.
#[derive(Clone, Default)]
struct LogSink(Arc<Mutex<Vec<u8>>>);
impl io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogSink;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A real HTTP transport that counts requests by method and can be failed on
/// demand (HTTP 503) to simulate an endpoint outage.
#[derive(Clone)]
struct Tap {
    inner: BoxTransport,
    calls: Arc<Mutex<BTreeMap<String, u64>>>,
    down: Arc<AtomicBool>,
}

impl Tap {
    fn total(&self) -> u64 {
        self.calls.lock().unwrap().values().sum()
    }
    fn count(&self, method: &str) -> u64 {
        self.calls.lock().unwrap().get(method).copied().unwrap_or(0)
    }
}

impl Service<RequestPacket> for Tap {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        for method in request.method_names() {
            *self
                .calls
                .lock()
                .unwrap()
                .entry(method.to_owned())
                .or_default() += 1;
        }
        if self.down.load(Ordering::SeqCst) {
            return Box::pin(async { Err(TransportErrorKind::http_error(503, String::new())) });
        }
        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(request).await })
    }
}

struct Live {
    urls: Vec<String>,
    logs: LogSink,
}

fn live() -> Option<Live> {
    let files = std::env::var("SAFENET_LIVE_RPC_FILES").ok()?;
    let urls = files
        .split(',')
        .map(|path| {
            std::fs::read_to_string(path.trim())
                .unwrap()
                .trim()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(urls.len(), 2, "exactly two endpoints");
    let logs = LogSink::default();
    let _ = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_env_filter("safenet_core=trace,alloy_transport_http=trace,info")
        .try_init();
    Some(Live { urls, logs })
}

impl Live {
    fn taps(&self) -> Vec<(Arc<str>, Tap)> {
        let names = ["primary", "secondary"];
        self.urls
            .iter()
            .zip(names)
            .map(|(url, name)| {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .build()
                    .unwrap();
                let transport = HttpTransport::new(client, SecretUrl::new(url.parse().unwrap()));
                let tap = Tap {
                    inner: BoxTransport::new(transport),
                    calls: Default::default(),
                    down: Default::default(),
                };
                (Arc::from(name), tap)
            })
            .collect()
    }

    async fn provider(
        &self,
        taps: &[(Arc<str>, Tap)],
        chain: u64,
        cooldown: Duration,
    ) -> Result<Provider, ConnectError> {
        Provider::from_transports(
            PoolConfig::new(Duration::from_secs(10), 3, cooldown),
            Some(chain),
            taps.iter()
                .map(|(n, t)| (n.clone(), BoxTransport::new(t.clone())))
                .collect(),
        )
        .await
    }

    /// No credential, and none of the secret URL path segments, in any log line.
    fn assert_logs_clean(&self) {
        let logs = String::from_utf8_lossy(&self.logs.0.lock().unwrap()).into_owned();
        for url in &self.urls {
            let parsed: reqwest::Url = url.parse().unwrap();
            for secret in parsed
                .path_segments()
                .into_iter()
                .flatten()
                .filter(|s| s.len() > 12)
            {
                if logs.contains(secret) {
                    for line in logs.lines().filter(|l| l.contains(secret)).take(3) {
                        eprintln!(
                            "LEAK LINE: {}",
                            line.replace(secret, "<KEY>")
                                .chars()
                                .take(400)
                                .collect::<String>()
                        );
                    }
                    panic!("credential path segment leaked into logs");
                }
            }
            assert!(!logs.contains(url.as_str()), "a full URL leaked into logs");
        }
        assert!(
            !logs.is_empty(),
            "expected some log output to have been captured"
        );
    }
}

fn index_config(start_block: u64) -> IndexConfig {
    IndexConfig {
        blocks: blocks::Config {
            block_time: BlockTime::Millis(12_000),
            max_reorg_depth: 2,
            start_block: Some(start_block),
            strict: true,
            ..Default::default()
        },
        events: events::Config {
            verify_integrity: true,
            ..Default::default()
        },
    }
}

/// Drives the watcher for `blocks` processed blocks, returning the numbers of
/// the blocks whose logs were emitted, in order, plus how many logs were seen.
async fn scan<E: events::Events>(
    watcher: &mut Watcher<E>,
    blocks: usize,
) -> (Vec<u64>, usize, Vec<events::EventLog<E>>) {
    let (mut processed, mut logs_seen, mut all) = (vec![], 0, vec![]);
    let (mut retries, deadline) = (0u32, std::time::Instant::now() + Duration::from_secs(150));
    while processed.len() < blocks {
        assert!(std::time::Instant::now() < deadline, "watcher stalled");
        // Like the driver: a failed step is retried after a short delay, and
        // the cursor never advances past a block that was not fully processed.
        let update = match watcher.next().await {
            Ok(update) => update,
            Err(err) => {
                retries += 1;
                println!("retry {retries}: {err}");
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        };
        match update {
            Update::Logs(update) => {
                processed.push(update.blocks.last);
                logs_seen += update.logs.len();
                all.extend(update.logs);
            }
            Update::Block(BlockUpdate::Uncle { number }) => {
                processed.retain(|n| *n < number);
            }
            Update::Block(_) => {}
        }
    }
    println!("scan: {} blocks, {retries} retried steps", processed.len());
    (processed, logs_seen, all)
}

#[tokio::test]
#[ignore = "needs SAFENET_LIVE_RPC_FILES"]
async fn startup_validation_and_sticky_primary() {
    let Some(live) = live() else { return };
    let taps = live.taps();

    // Wrong expected chain: the whole configuration is rejected, without echoing URLs.
    let err = live
        .provider(&taps, 100, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            ConnectError::ChainId {
                expected: 100,
                actual: 1,
                ..
            }
        ),
        "{err}"
    );
    assert!(!format!("{err} {err:?}").contains("infura"));

    // Both endpoints validate as mainnet with the same genesis hash.
    let provider = live
        .provider(&taps, 1, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(provider.chain_id(), 1);
    let pool = provider.pool().unwrap().clone();
    assert_eq!(&*pool.active_name(), "primary");
    let secondary_before = taps[1].1.total();

    // Sticky, not round-robin: 12 requests all go to the primary.
    let primary_before = taps[0].1.total();
    for _ in 0..12 {
        provider.get_block_number().await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await; // stay under free-tier burst limits
    }
    assert_eq!(taps[0].1.total() - primary_before, 12);
    assert_eq!(
        taps[1].1.total(),
        secondary_before,
        "secondary must be idle"
    );
    assert_eq!(pool.epoch(), 0);
    live.assert_logs_clean();
}

#[tokio::test]
#[ignore = "needs SAFENET_LIVE_RPC_FILES"]
async fn per_block_scan_with_real_logs() {
    let Some(live) = live() else { return };
    let taps = live.taps();
    let provider = live
        .provider(&taps, 1, Duration::from_secs(5))
        .await
        .unwrap();
    let head = provider.get_block_number().await.unwrap();
    let start = head - 25;

    let mut watcher =
        Watcher::<Weth::WethEvents>::new(provider.clone(), index_config(start), vec![WETH], None)
            .await
            .unwrap();
    let (blocks, logs, all) = scan(&mut watcher, 15).await;

    // Every block from start, contiguous, none skipped (blocks without logs too).
    assert_eq!(blocks, (start..start + 15).collect::<Vec<_>>());
    assert!(logs > 0, "WETH emits logs nearly every block");
    // Only the configured contract and its event topics; sorted by (block, index).
    assert!(all.iter().all(|l| l.address == WETH));
    assert!(
        all.windows(2)
            .all(|w| (w[0].block, w[0].index) < (w[1].block, w[1].index))
    );
    // Per-block exact-hash queries, restricted by address+topics; no range queries.
    let pool = provider.pool().unwrap();
    println!(
        "getLogs primary={} secondary={} epoch={} active={} status={:?}",
        taps[0].1.count("eth_getLogs"),
        taps[1].1.count("eth_getLogs"),
        pool.epoch(),
        pool.active_name(),
        pool.status()
            .iter()
            .map(|s| (s.name.to_string(), s.circuit, s.consecutive_failures))
            .collect::<Vec<_>>()
    );
    assert!(taps[0].1.count("eth_getLogs") + taps[1].1.count("eth_getLogs") >= 15);
    assert!(taps[0].1.count("eth_getBlockByNumber") > 0);
    live.assert_logs_clean();
}

#[tokio::test]
#[ignore = "needs SAFENET_LIVE_RPC_FILES"]
async fn bloom_positive_empty_logs_are_verified_against_the_secondary() {
    let Some(live) = live() else { return };
    let taps = live.taps();
    let provider = live
        .provider(&taps, 1, Duration::from_secs(5))
        .await
        .unwrap();
    let head = provider.get_block_number().await.unwrap();

    // WETH never emits `Sync`, but the bloom usually contains both the WETH
    // address and the Sync topic, so each block's empty answer is checked with
    // the secondary. Both agree on empty, so the cursor advances.
    let mut watcher = Watcher::<Pair::PairEvents>::new(
        provider.clone(),
        index_config(head - 20),
        vec![WETH],
        None,
    )
    .await
    .unwrap();
    let secondary_logs_before = taps[1].1.count("eth_getLogs");
    let (blocks, logs, _) = scan(&mut watcher, 12).await;
    assert_eq!(blocks.len(), 12);
    assert_eq!(logs, 0);
    let verified = taps[1].1.count("eth_getLogs") - secondary_logs_before;
    println!("secondary verification queries: {verified} of 12 blocks");
    assert!(
        verified > 0,
        "a possibly-matching bloom must trigger verification"
    );
    // Verification is not round-robin: it happens only for those blocks.
    assert!(verified <= 12);
    assert_eq!(provider.pool().unwrap().epoch(), 0);
    live.assert_logs_clean();
}

#[tokio::test]
#[ignore = "needs SAFENET_LIVE_RPC_FILES"]
async fn endpoints_agree_on_real_logs() {
    let Some(live) = live() else { return };
    let taps = live.taps();
    let provider = live
        .provider(&taps, 1, Duration::from_secs(5))
        .await
        .unwrap();
    let head = provider.get_block_number().await.unwrap();
    let block = provider
        .get_block_by_number((head - 10).into())
        .await
        .unwrap()
        .unwrap();
    let filter = alloy::rpc::types::Filter::new()
        .at_block_hash(block.header.hash)
        .address(WETH);
    let primary = provider.get_logs(&filter).await.unwrap();
    let (name, secondary) = provider.secondary().expect("a secondary is available");
    let other = secondary.get_logs(&filter).await.unwrap();
    println!(
        "{} WETH logs at block {}; secondary {name} agrees",
        primary.len(),
        head - 10
    );
    let key = |l: &alloy::rpc::types::Log| {
        (
            l.transaction_hash,
            l.log_index,
            l.address(),
            l.topics().to_vec(),
            l.data().data.clone(),
        )
    };
    assert_eq!(
        primary.iter().map(key).collect::<BTreeSet<_>>(),
        other.iter().map(key).collect::<BTreeSet<_>>()
    );
}

#[tokio::test]
#[ignore = "needs SAFENET_LIVE_RPC_FILES"]
async fn failover_mid_scan_never_skips_a_block_and_primary_is_restored_between_blocks() {
    let Some(live) = live() else { return };
    let taps = live.taps();
    let cooldown = Duration::from_secs(4);

    // The free Infura key throttles at random; retry until it validates so the
    // primary really is the primary.
    let mut provider = None;
    for _ in 0..6 {
        let candidate = live.provider(&taps, 1, cooldown).await.unwrap();
        if &*candidate.pool().unwrap().active_name() == "primary" {
            provider = Some(candidate);
            break;
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
    let provider = provider.expect("primary never validated");
    let pool = provider.pool().unwrap().clone();
    let head = provider.get_block_number().await.unwrap();
    let start = head - 110;

    let mut watcher =
        Watcher::<Weth::WethEvents>::new(provider.clone(), index_config(start), vec![WETH], None)
            .await
            .unwrap();
    let (mut blocks, _, _) = scan(&mut watcher, 6).await;
    // The real Infura may already have tripped by itself (a genuine failover);
    // wait until the primary is restored so the injected outage is meaningful.
    for _ in 0..8 {
        if &*pool.active_name() == "primary" {
            break;
        }
        println!("primary not active yet (organic failover); waiting for restore");
        tokio::time::sleep(cooldown + Duration::from_secs(1)).await;
        let (more, _, _) = scan(&mut watcher, 3).await;
        blocks.extend(more);
    }
    assert_eq!(&*pool.active_name(), "primary");
    let epoch_before = pool.epoch();

    // Force an outage of the primary: consecutive retryable failures open its
    // circuit and the secondary takes over; the scan carries on with no gap.
    taps[0].1.down.store(true, Ordering::SeqCst);
    let (more, _, _) = scan(&mut watcher, 8).await;
    blocks.extend(more);
    assert_eq!(&*pool.active_name(), "secondary");
    assert!(pool.epoch() > epoch_before);
    assert_eq!(pool.status()[0].circuit, Circuit::Open);
    assert!(taps[1].1.count("eth_getLogs") > 0);
    // No request reached the failed primary while its circuit was open (only
    // the ones that tripped it, before the switch).
    let primary_while_open = taps[0].1.total();

    // The primary recovers. Its cooldown elapses, yet it is not used mid-block;
    // it is only restored at a block boundary (a few attempts, as the real
    // Infura may itself throttle the probe).
    taps[0].1.down.store(false, Ordering::SeqCst);
    tokio::time::sleep(cooldown + Duration::from_secs(1)).await;
    assert_eq!(&*pool.active_name(), "secondary", "no mid-block move back");
    for _ in 0..6 {
        let (more, _, _) = scan(&mut watcher, 3).await;
        blocks.extend(more);
        if &*pool.active_name() == "primary" {
            break;
        }
        tokio::time::sleep(cooldown + Duration::from_secs(1)).await;
    }
    assert_eq!(&*pool.active_name(), "primary", "restored between blocks");
    assert!(taps[0].1.total() >= primary_while_open);

    // Across the switches: contiguous, in order, nothing skipped or repeated.
    assert_eq!(
        blocks,
        (start..start + blocks.len() as u64).collect::<Vec<_>>()
    );
    println!(
        "blocks processed across failover and restore: {}",
        blocks.len()
    );
    live.assert_logs_clean();
}
