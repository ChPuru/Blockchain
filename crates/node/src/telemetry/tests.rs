#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use super::*;

#[test]
fn every_metric_name_is_distinct_and_prefixed() {
    let unique: BTreeSet<&&str> = ALL_METRICS.iter().collect();
    assert_eq!(unique.len(), ALL_METRICS.len(), "a metric name is listed twice");
    for name in ALL_METRICS {
        assert!(name.starts_with("ferrum_"), "{name} is not namespaced");
        assert_eq!(name.to_ascii_lowercase(), **name, "{name} is not snake_case");
    }
}

#[test]
fn counters_carry_the_total_suffix_and_gauges_do_not() {
    // Prometheus convention: a monotonic counter ends in `_total`.
    for name in [
        METRIC_BLOCKS_ACCEPTED,
        METRIC_BLOCKS_REJECTED,
        METRIC_BLOCKS_MINED,
        METRIC_REORGS,
        METRIC_TXS_ACCEPTED,
        METRIC_TXS_REJECTED,
        METRIC_HEADERS_ACCEPTED,
        METRIC_PEERS_BANNED,
        METRIC_SHED,
    ] {
        assert!(name.ends_with("_total"), "{name} is a counter and needs _total");
    }
    for name in [METRIC_HEIGHT, METRIC_PEERS, METRIC_MEMPOOL_TXS, METRIC_REORG_DEPTH] {
        assert!(!name.ends_with("_total"), "{name} is a gauge");
    }
}

#[test]
fn the_contract_metrics_all_exist() {
    // CONTRACT 13: height, peers, mempool size, blocks accepted/rejected,
    // reorg depth.
    for required in [
        METRIC_HEIGHT,
        METRIC_PEERS,
        METRIC_MEMPOOL_TXS,
        METRIC_BLOCKS_ACCEPTED,
        METRIC_BLOCKS_REJECTED,
        METRIC_REORG_DEPTH,
    ] {
        assert!(ALL_METRICS.contains(&required), "{required} is missing");
    }
}

#[test]
fn a_fresh_metric_set_is_all_zero() {
    assert_eq!(NodeMetrics::new().snapshot(), MetricsSnapshot::default());
}

#[test]
fn gauges_take_the_last_value_and_counters_accumulate() {
    let m = NodeMetrics::new();
    m.set_height(1);
    m.set_height(42);
    m.set_peers(3);
    m.set_mempool(7, 2048);
    m.block_accepted();
    m.block_accepted();
    m.block_rejected();
    m.block_mined();
    m.tx_accepted();
    m.tx_rejected();
    m.headers_accepted(2000);
    m.peer_disconnected();
    m.shed();
    m.reorg(6);

    let s = m.snapshot();
    assert_eq!(s.height, 42, "a gauge keeps the last value, not the sum");
    assert_eq!(s.peers, 3);
    assert_eq!(s.mempool_txs, 7);
    assert_eq!(s.mempool_bytes, 2048);
    assert_eq!(s.blocks_accepted, 2);
    assert_eq!(s.blocks_rejected, 1);
    assert_eq!(s.blocks_mined, 1);
    assert_eq!(s.txs_accepted, 1);
    assert_eq!(s.txs_rejected, 1);
    assert_eq!(s.headers_accepted, 2000);
    assert_eq!(s.peers_disconnected, 1);
    assert_eq!(s.shed, 1);
    assert_eq!(s.reorgs, 1);
    assert_eq!(s.reorg_depth, 6);
}

#[test]
fn a_gauge_value_saturates_rather_than_wrapping() {
    assert_eq!(gauge_value(0), 0);
    assert_eq!(gauge_value(1_000), 1_000);
    assert_eq!(gauge_value(u64::from(u32::MAX)), u32::MAX);
    assert_eq!(gauge_value(u64::MAX), u32::MAX, "a wrapped height would read as tiny");
}

#[test]
fn the_reorg_line_matches_what_the_devnet_script_greps_for() {
    // devnet/heal.sh: grep -iE 'reorg|disconnect|rolled back|new tip'
    let line = reorg_line(6, 7).to_ascii_lowercase();
    let matched: Vec<&&str> = REORG_LOG_NEEDLES.iter().filter(|n| line.contains(**n)).collect();
    assert!(!matched.is_empty(), "heal.sh would find nothing in {line:?}");
    assert!(line.contains("reorg"));
    assert!(line.contains("rolled back"));
    assert!(line.contains("new tip"));
}

#[test]
fn the_reorg_line_names_both_counts() {
    let line = reorg_line(3, 5);
    assert!(line.contains('3'), "{line}");
    assert!(line.contains('5'), "{line}");
}

#[test]
fn logging_a_reorg_does_not_panic_without_a_subscriber() {
    // tracing is a no-op with no subscriber installed; the call must still
    // be safe, because the node logs before telemetry is up in tests.
    log_reorg(&BlockHash::ZERO, &BlockHash::ZERO, 1, 2);
}

#[test]
fn the_default_log_filter_parses() {
    assert!(tracing_subscriber::EnvFilter::try_new(DEFAULT_LOG_FILTER).is_ok());
}

#[test]
fn describing_metrics_without_a_recorder_is_a_no_op() {
    describe_metrics();
    let m = NodeMetrics::new();
    m.set_height(9);
    assert_eq!(m.snapshot().height, 9);
}
