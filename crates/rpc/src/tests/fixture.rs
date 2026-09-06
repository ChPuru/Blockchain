//! An in-memory devnet chain, a stub mempool and a stub network.
//!
//! The chain is real: a `redb` store with the reverse index on, a
//! `ChainManager`, a `PowEngine`, and blocks that satisfy their own target.
//! Only the mempool and the peer-to-peer service are stubs, because there is no
//! mempool crate to depend on yet and because a libp2p swarm in a unit test
//! tests libp2p.

use std::sync::Arc;

use ferrum_chain::{ChainManager, StoreHeaderView, build_coinbase_script_sig, compute_merkle_root};
use ferrum_consensus::{
    EngineRouter, HeaderView, PowEngine, compact_to_target, hash_meets_target,
};
use ferrum_crypto::{Address, PublicKey, SecretKey};
use ferrum_script::SigHashType;
use ferrum_storage::{Store, StoreConfig, header_hash, txid};
use ferrum_types::{
    Amount, Block, BlockHash, BlockHeader, BlockSeal, ChainParams, Coin, OutPoint, Script,
    Transaction, TxIn, TxOut, Txid,
};
use parking_lot::Mutex;

use crate::adapters::ChainHandle;
use crate::context::NodeContext;
use crate::error::RpcError;
use crate::provider::{
    ChainProvider, MempoolProvider, MempoolTx, NetworkProvider, NetworkSummary, PeerSummary,
};

/// Coinbase maturity in the fixture.
///
/// Two blocks rather than the network's hundred: the tests are about the RPC
/// surface, and mining a hundred blocks to spend one output would make every
/// one of them slower without testing anything extra. The maturity *rule* is
/// still exercised — the tip's own coinbase is always immature.
pub(crate) const FIXTURE_MATURITY: u64 = 2;

/// Devnet parameters with a short maturity window.
#[must_use]
pub(crate) fn params() -> ChainParams {
    ChainParams { coinbase_maturity: FIXTURE_MATURITY, ..ChainParams::devnet() }
}

/// A deterministic key, so every run produces the same addresses.
#[must_use]
pub(crate) fn key(byte: u8) -> (SecretKey, PublicKey) {
    let secret = SecretKey::from_bytes(&[byte; 32]).expect("a fixed 32-byte scalar is valid");
    let public = secret.public_key();
    (secret, public)
}

/// The address a key pays to on devnet.
#[must_use]
pub(crate) fn address(byte: u8) -> Address {
    let (_, public) = key(byte);
    Address::p2pkh(ferrum_types::Network::Devnet, &public)
}

/// A whole chain, in memory, with the reverse index on.
#[derive(Debug)]
pub(crate) struct TestChain {
    /// The store.
    pub(crate) store: Arc<Store>,
    /// The manager.
    pub(crate) chain: Arc<ChainManager>,
    /// The engines.
    pub(crate) engines: Arc<EngineRouter>,
    /// The parameters in force.
    pub(crate) params: ChainParams,
}

impl TestChain {
    /// A fresh chain with genesis connected.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_index(true)
    }

    /// A fresh chain, with or without the reverse index.
    #[must_use]
    pub(crate) fn with_index(index: bool) -> Self {
        let params = params();
        let cfg = if index { StoreConfig::indexed() } else { StoreConfig::default() }
            .with_chain_id(params.chain_id);
        let store = Arc::new(Store::open_in_memory(cfg).expect("in-memory store opens"));
        let engines = Arc::new(EngineRouter::new(params.clone()).expect("router builds"));
        let chain = Arc::new(
            ChainManager::open(Arc::clone(&store), params.clone(), Arc::clone(&engines))
                .expect("manager opens"),
        );
        chain.init_genesis().expect("genesis initialises");
        TestChain { store, chain, engines, params }
    }

    /// The active tip.
    #[must_use]
    pub(crate) fn tip(&self) -> (BlockHash, u64) {
        self.chain.tip()
    }

    /// The header of a stored block.
    #[must_use]
    pub(crate) fn header(&self, hash: &BlockHash) -> BlockHeader {
        self.store.get_header(hash).expect("read").expect("known block").header
    }

    /// Mine one block on the tip, paying the coinbase to `payout`.
    ///
    /// `txs` go in after the coinbase, and their fees are added to the reward
    /// so the coinbase claims exactly what it is owed.
    pub(crate) fn mine_to(&self, payout: &Script, txs: Vec<Transaction>, extra_nonce: u64) -> Block {
        let (tip, _) = self.tip();
        let entry = self.store.get_header(&tip).expect("read").expect("known tip");
        let height = entry.height.saturating_add(1);
        let view = StoreHeaderView::new(&self.store, &self.params);
        let engine = self.engines.engine_for_height(height);
        let bits = engine.next_bits(&entry.header, &view).expect("next bits");
        let mtp_s = view.median_time_past(&tip).unwrap_or(0);
        let timestamp_ms = entry
            .header
            .timestamp_ms
            .saturating_add(self.params.target_spacing_ms)
            .max(mtp_s.saturating_mul(1_000).saturating_add(1));

        let fees = self.fees_of(&txs);
        let reward = self.params.block_subsidy(height).checked_add(fees).expect("reward fits");
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(
                build_coinbase_script_sig(height, &extra_nonce.to_le_bytes())
                    .expect("extra nonce fits the coinbase window"),
            )],
            outputs: vec![TxOut::new(reward, payout.clone())],
            lock_time: 0,
        };

        let mut all = vec![coinbase];
        all.extend(txs);
        let header = seal(BlockHeader {
            version: 1,
            prev_hash: tip,
            merkle_root: compute_merkle_root(&all),
            timestamp_ms,
            bits,
            nonce: 0,
        });
        Block::new(header, all, BlockSeal::POW)
    }

    /// Mine a block and connect it, returning its hash.
    pub(crate) fn mine_and_connect(&self, payout: &Script, txs: Vec<Transaction>, extra: u64) -> BlockHash {
        let block = self.mine_to(payout, txs, extra);
        let hash = header_hash(&block.header);
        self.chain.accept_block(block).expect("the fixture mines valid blocks");
        hash
    }

    /// Total fees of a set of transactions, resolved against the UTXO set.
    fn fees_of(&self, txs: &[Transaction]) -> Amount {
        let mut total = Amount::ZERO;
        for tx in txs {
            let mut inputs = Amount::ZERO;
            for input in &tx.inputs {
                if let Ok(Some(coin)) = self.store.get_coin(&input.prev_out) {
                    inputs = inputs.saturating_add(coin.value);
                }
            }
            let outputs = tx.total_output().unwrap_or(Amount::ZERO);
            total = total.saturating_add(inputs.saturating_sub(outputs));
        }
        total
    }

    /// A [`ChainProvider`] over this chain.
    #[must_use]
    pub(crate) fn provider(&self, index: bool) -> Arc<dyn ChainProvider> {
        Arc::new(ChainHandle::new(Arc::clone(&self.chain), index))
    }
}

/// Grind a nonce until the header meets its own target.
///
/// Devnet's limit accepts about half of all hashes, so this loop runs a couple
/// of times.
#[must_use]
pub(crate) fn seal(mut header: BlockHeader) -> BlockHeader {
    let target = compact_to_target(header.bits).expect("fixture bits expand");
    loop {
        if hash_meets_target(&header_hash(&header), target) {
            return header;
        }
        PowEngine::advance_search(&mut header);
    }
}

/// Sign a one-input P2PKH spend.
///
/// Uses `ferrum-wallet`'s signer so the fixture's transactions are signed the
/// same way a real wallet signs them; a hand-rolled signature that happened to
/// verify would prove nothing about the RPC surface.
#[must_use]
pub(crate) fn spend_p2pkh(
    prevout: (OutPoint, Coin),
    secret: &SecretKey,
    to: &Script,
    value: Amount,
    chain_id: ferrum_types::ChainId,
) -> Transaction {
    let (out_point, coin) = prevout;
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn::new(out_point, Script::EMPTY)],
        outputs: vec![TxOut::new(value, to.clone())],
        lock_time: 0,
    };
    ferrum_wallet::sign_p2pkh_input(&mut tx, 0, &coin, secret, chain_id, SigHashType::ALL)
        .expect("the fixture signs a P2PKH input it just created");
    tx
}

/// The outpoint and coin of a block's coinbase output 0.
#[must_use]
pub(crate) fn coinbase_output(block: &Block, height: u64) -> (OutPoint, Coin) {
    let coinbase = block.txs.first().expect("every fixture block has a coinbase");
    let out_point = OutPoint::new(txid(coinbase), 0);
    let output = coinbase.outputs.first().expect("the fixture coinbase pays one output");
    (
        out_point,
        Coin {
            value: output.value,
            script_pubkey: output.script_pubkey.clone(),
            height,
            is_coinbase: true,
        },
    )
}

/// A mempool that holds whatever it is given, in txid order.
///
/// `reject` makes every submission fail, for the tests that check the error
/// path. There is no policy here on purpose: policy belongs to
/// `ferrum-mempool`, and duplicating it in a fixture would test the copy.
#[derive(Debug, Default)]
pub(crate) struct StubMempool {
    entries: Mutex<std::collections::BTreeMap<Txid, MempoolTx>>,
    reject: Mutex<Option<String>>,
    max_bytes: usize,
    min_fee_rate: u64,
}

impl StubMempool {
    /// An empty pool with an 8 MiB budget and a 1 000-grain floor.
    #[must_use]
    pub(crate) fn new() -> Self {
        StubMempool {
            entries: Mutex::new(std::collections::BTreeMap::new()),
            reject: Mutex::new(None),
            max_bytes: 8 * 1024 * 1024,
            min_fee_rate: 1_000,
        }
    }

    /// Make every submission fail with this message.
    pub(crate) fn reject_with(&self, reason: &str) {
        *self.reject.lock() = Some(reason.to_owned());
    }

    /// Put a transaction in directly, as if it had been accepted.
    pub(crate) fn insert(&self, tx: Transaction, fee: Amount, added_height: u64) -> Txid {
        let id = txid(&tx);
        let size = tx.serialized_size();
        let fee_rate = crate::handlers::convert::fee_rate(fee, size);
        self.entries
            .lock()
            .insert(id, MempoolTx { tx, fee, size, fee_rate, added_height });
        id
    }
}

impl MempoolProvider for StubMempool {
    fn len(&self) -> usize {
        self.entries.lock().len()
    }

    fn size_bytes(&self) -> usize {
        self.entries.lock().values().map(|e| e.size).sum()
    }

    fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    fn min_fee_rate(&self) -> u64 {
        self.min_fee_rate
    }

    fn txids(&self) -> Vec<Txid> {
        self.entries.lock().keys().copied().collect()
    }

    fn get(&self, id: &Txid) -> Option<MempoolTx> {
        self.entries.lock().get(id).cloned()
    }

    fn submit(&self, tx: Transaction) -> Result<Txid, RpcError> {
        if let Some(reason) = self.reject.lock().clone() {
            return Err(RpcError::new(crate::error::RpcErrorCode::TxRejected, reason));
        }
        Ok(self.insert(tx, Amount::from_grains(1_000), 0))
    }

    fn select_for_block(&self, max_bytes: usize) -> Vec<Transaction> {
        let mut out = Vec::new();
        let mut used = 0usize;
        for entry in self.entries.lock().values() {
            if used.saturating_add(entry.size) > max_bytes {
                break;
            }
            used = used.saturating_add(entry.size);
            out.push(entry.tx.clone());
        }
        out
    }
}

/// A peer-to-peer service with a fixed peer list and a broadcast counter.
#[derive(Debug, Default)]
pub(crate) struct StubNetwork {
    peers: Vec<PeerSummary>,
    broadcasts: Mutex<u32>,
}

impl StubNetwork {
    /// A service reporting `count` peers.
    #[must_use]
    pub(crate) fn with_peers(count: usize) -> Self {
        let peers = (0..count)
            .map(|i| PeerSummary {
                peer_id: format!("12D3KooWStubPeer{i:04}"),
                address: Some(format!("/ip4/10.0.0.{i}/tcp/8655")),
                agent_version: Some("ferrum/0.1.0".to_owned()),
                protocol_version: Some("/ferrum/1.0.0".to_owned()),
                last_rtt_ms: Some(12),
                is_static: i == 0,
            })
            .collect();
        StubNetwork { peers, broadcasts: Mutex::new(0) }
    }

    /// How many messages were announced.
    #[must_use]
    pub(crate) fn broadcast_count(&self) -> u32 {
        *self.broadcasts.lock()
    }
}

#[async_trait::async_trait]
impl NetworkProvider for StubNetwork {
    async fn peers(&self) -> Vec<PeerSummary> {
        self.peers.clone()
    }

    async fn network_info(&self) -> NetworkSummary {
        NetworkSummary {
            local_peer_id: "12D3KooWStubLocal".to_owned(),
            protocol_version: "/ferrum/1.0.0".to_owned(),
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/8655".to_owned()],
            peer_count: self.peers.len(),
            shed_total: 0,
        }
    }

    async fn broadcast_tx(&self, _tx: Transaction) -> Result<(), RpcError> {
        *self.broadcasts.lock() += 1;
        Ok(())
    }

    async fn broadcast_block(&self, _block: Block) -> Result<(), RpcError> {
        *self.broadcasts.lock() += 1;
        Ok(())
    }
}

/// A chain with blocks, plus the pieces every test wants.
#[derive(Debug)]
pub(crate) struct Fixture {
    /// The chain.
    pub(crate) chain: TestChain,
    /// The stub mempool.
    pub(crate) mempool: Arc<StubMempool>,
    /// The stub network.
    pub(crate) network: Arc<StubNetwork>,
    /// The address the coinbases pay.
    pub(crate) miner: Address,
    /// The miner's key, for signing spends.
    pub(crate) miner_key: SecretKey,
    /// A second address, for the spend.
    pub(crate) recipient: Address,
    /// The hashes of the connected blocks, height order from 1.
    pub(crate) blocks: Vec<BlockHash>,
    /// The transaction that spends block 1's coinbase, once it is confirmed.
    pub(crate) spend_txid: Option<Txid>,
    /// Whether the store carries the reverse index.
    pub(crate) indexed: bool,
}

impl Fixture {
    /// A chain of `blocks` mined blocks paying [`Fixture::miner`], plus one
    /// spend to [`Fixture::recipient`] in the last block.
    #[must_use]
    pub(crate) fn build(blocks: usize, with_spend: bool) -> Self {
        Self::build_with_index(blocks, with_spend, true)
    }

    /// [`Fixture::build`], with the reverse index optionally off.
    #[must_use]
    pub(crate) fn build_with_index(blocks: usize, with_spend: bool, index: bool) -> Self {
        let chain = TestChain::with_index(index);
        let (miner_key, miner_public) = key(1);
        let miner = Address::p2pkh(ferrum_types::Network::Devnet, &miner_public);
        let recipient = address(2);
        let payout = miner.script_pubkey();

        let mut hashes = Vec::new();
        let mut first_block: Option<Block> = None;
        for i in 0..blocks {
            let block = chain.mine_to(&payout, Vec::new(), u64::try_from(i).unwrap_or(0));
            let hash = header_hash(&block.header);
            if first_block.is_none() {
                first_block = Some(block.clone());
            }
            chain.chain.accept_block(block).expect("the fixture mines valid blocks");
            hashes.push(hash);
        }

        let mut spend_txid = None;
        if with_spend
            && let Some(first) = first_block
        {
            let (out_point, coin) = coinbase_output(&first, 1);
            let value = coin.value.checked_sub(Amount::from_grains(10_000)).unwrap_or(coin.value);
            let tx = spend_p2pkh(
                (out_point, coin),
                &miner_key,
                &recipient.script_pubkey(),
                value,
                chain.params.chain_id,
            );
            spend_txid = Some(txid(&tx));
            let hash = chain.mine_and_connect(&payout, vec![tx], 9_999);
            hashes.push(hash);
        }

        Fixture {
            chain,
            mempool: Arc::new(StubMempool::new()),
            network: Arc::new(StubNetwork::with_peers(3)),
            miner,
            miner_key,
            recipient,
            blocks: hashes,
            spend_txid,
            indexed: index,
        }
    }

    /// A [`ChainProvider`] over this fixture's chain.
    #[must_use]
    pub(crate) fn provider(&self) -> Arc<dyn ChainProvider> {
        self.chain.provider(self.indexed)
    }

    /// A context wired to the chain, the stub mempool and the stub network.
    #[must_use]
    pub(crate) fn context(&self) -> NodeContext {
        NodeContext::new(self.provider())
            .with_mempool(Arc::clone(&self.mempool) as Arc<dyn MempoolProvider>)
            .with_network(Arc::clone(&self.network) as Arc<dyn NetworkProvider>)
    }

    /// The tip height.
    #[must_use]
    pub(crate) fn tip_height(&self) -> u64 {
        self.chain.tip().1
    }

    /// The tip hash.
    #[must_use]
    pub(crate) fn tip_hash(&self) -> BlockHash {
        self.chain.tip().0
    }
}
