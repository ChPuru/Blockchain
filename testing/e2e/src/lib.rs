//! End-to-end multi-node integration tests for Ferrum (CONTRACT §14, M6).
//!
//! `devnet/ci-e2e.sh` proves the same properties by starting four `chaind`
//! processes, poking them over JSON-RPC with `curl` and grepping their logs. It
//! is the honest test — it exercises the real binary, the real command line and
//! a real SIGKILL — and it takes minutes, needs `bash`, and only runs in CI.
//!
//! This crate is the fast equivalent that runs on **every** `cargo test`. The
//! nodes are real [`ferrum_node::Node`] instances in one process, wired to each
//! other over real TCP on loopback through the real libp2p stack: real Noise
//! handshakes, real gossipsub meshes, real headers-first sync, real `redb`
//! stores in real temporary directories. Nothing is mocked. What is *not* real
//! is the process boundary, and [`harness::TestNet::kill`] documents exactly
//! what that costs.
//!
//! # What the harness gives you
//!
//! ```no_run
//! use std::time::Duration;
//! use ferrum_e2e::harness::TestNet;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let mut net = TestNet::spawn(4).await?;      // four nodes, full mesh
//! net.await_peers(Duration::from_secs(30)).await?;
//! net.mine_blocks(0, 5).await?;                // node 0 mines five blocks
//! net.await_convergence(Duration::from_secs(60)).await?;
//!
//! net.partition(&[0, 1], &[2, 3]).await?;      // 2 | 2
//! net.mine_blocks(0, 6).await?;                // the winning branch
//! net.mine_blocks(2, 2).await?;                // the losing branch
//! net.heal().await?;
//! net.await_convergence(Duration::from_secs(120)).await?;
//! net.shutdown().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Three properties every test here depends on
//!
//! 1. **Mining is driven, not ambient.** No node runs with `--mine`; the
//!    harness seals exactly the blocks a test asks for, on exactly the node it
//!    asks. A background miner would make "mine two blocks on this side of the
//!    partition and six on that one" a race rather than an assertion.
//! 2. **Devnet's `pow_limit` is `0x7fff…`**, so sealing is one or two hashes
//!    and a hundred-block chain costs milliseconds of CPU. The clock budget in
//!    these tests is spent on `redb` commits and TCP round trips, which is why
//!    every timeout is generous but finite.
//! 3. **A failure prints the whole network.** Every wait returns an error whose
//!    message is [`harness::TestNet::describe`] — per node: alive, height, tip,
//!    cumulative work, peer count, mempool size — because a CI log that says
//!    only "did not converge" costs an afternoon.
//!
//! # Layout
//!
//! | Module | What it owns |
//! |---|---|
//! | [`harness`] | [`harness::TestNet`], the whole public surface |
//! | [`harness::ports`] | ephemeral loopback port reservation |
//! | [`harness::config`] | node configuration and partition topology |
//! | [`harness::lifecycle`] | start, kill, restart, partition, heal |
//! | [`harness::mining`] | driven sealing, announcement, forged blocks |
//! | [`harness::spend`] | building and submitting a real payment |
//! | [`harness::report`] | the diagnostics a failing test prints |

#![warn(missing_docs)]

pub mod harness;

pub use crate::harness::TestNet;
