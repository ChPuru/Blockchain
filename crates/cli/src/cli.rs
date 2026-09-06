//! The `chain-cli` command surface, exactly as CONTRACT §13.1 fixes it.
//!
//! ```text
//! chain-cli [--datadir DIR] [--rpc URL] <group> <command>
//!
//!   wallet   new | restore | address | balance | send | list-unspent
//!            dump-seed | dump-pubkey
//!   tx       decode | send | get
//!   block    get | hash | tip
//!   script   eval | disassemble | build-p2pkh | build-multisig | build-htlc
//!   chain    info | peers | stateroot | reindex
//!   genesis  mine
//!   faucet   request
//! ```
//!
//! Two rules hold across the whole surface and are worth stating once:
//!
//! - **`--datadir` and `--rpc` are global**, accepted before the subcommand,
//!   because `devnet/fork.sh` and `devnet/ci-e2e.sh` write them there.
//! - **There is no `--passphrase` flag.** A passphrase reaches the process
//!   through `--passphrase-file` or a terminal prompt and never through the
//!   argument vector, which every other process on the machine can read. See
//!   [`crate::passphrase`].

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::passphrase::PassphraseSource;

/// `chain-cli` — the Ferrum wallet and admin client.
#[derive(Debug, Parser)]
#[command(
    name = "chain-cli",
    version,
    about = "Ferrum wallet and admin client",
    long_about = "Talks to a running chaind over JSON-RPC, and owns the local wallet keystore.\n\
                  Every read command accepts --json; without it the bare value is the last line \n\
                  of stdout, so `| tail -1` works.",
    propagate_version = true
)]
pub struct ChainCli {
    /// Directory holding the wallet keystore and, for `chain reindex`, the store.
    #[arg(long, global = true, value_name = "DIR", env = crate::paths::DATADIR_ENV)]
    pub datadir: Option<PathBuf>,

    /// JSON-RPC endpoint of the node to talk to.
    #[arg(long, global = true, value_name = "URL", env = crate::rpc::RPC_ENV)]
    pub rpc: Option<String>,

    /// Machine-readable output. Suppresses the human lines and the bare value.
    #[arg(long, global = true)]
    pub json: bool,

    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The top-level command groups.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Keys, addresses, balances and spending.
    #[command(subcommand)]
    Wallet(WalletCmd),
    /// Raw transactions.
    #[command(subcommand)]
    Tx(TxCmd),
    /// Blocks and the tip.
    #[command(subcommand)]
    Block(BlockCmd),
    /// The script virtual machine.
    #[command(subcommand)]
    Script(ScriptCmd),
    /// Chain state and node administration.
    #[command(subcommand)]
    Chain(ChainCmd),
    /// Genesis block construction for a new network.
    #[command(subcommand)]
    Genesis(GenesisCmd),
    /// The devnet faucet.
    #[command(subcommand)]
    Faucet(FaucetCmd),
}

/// How to obtain the keystore passphrase, shared by every wallet command.
#[derive(Debug, Args, Clone)]
pub struct PassphraseArgs {
    /// Read the passphrase from this file (one trailing newline is trimmed).
    #[arg(long, value_name = "FILE")]
    pub passphrase_file: Option<PathBuf>,

    /// Prompt for the passphrase on the terminal.
    ///
    /// Off by default so that unattended callers such as `devnet/fork.sh`,
    /// whose stdin is still a terminal, cannot hang on an invisible prompt.
    #[arg(long)]
    pub prompt_passphrase: bool,
}

impl PassphraseArgs {
    /// Turn the flags into a [`PassphraseSource`].
    #[must_use]
    pub fn source(&self) -> PassphraseSource {
        PassphraseSource {
            file: self.passphrase_file.clone(),
            prompt: self.prompt_passphrase,
        }
    }
}

/// `chain-cli wallet ...`
#[derive(Debug, Subcommand)]
pub enum WalletCmd {
    /// Create a wallet. Prints the new address; the mnemonic goes elsewhere.
    New {
        /// Write the mnemonic here instead of to stderr.
        ///
        /// With this flag the mnemonic never touches stdout, so `| tail -1`
        /// still yields the address.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Mnemonic length: 12, 15, 18, 21 or 24 words.
        #[arg(long, default_value_t = 12, value_name = "N")]
        words: usize,

        /// Which network the addresses belong to.
        #[arg(long, default_value = "devnet", value_name = "NAME")]
        network: String,

        /// Overwrite an existing keystore at this datadir.
        #[arg(long)]
        force: bool,

        #[command(flatten)]
        passphrase: PassphraseArgs,
    },

    /// Restore a wallet from a BIP-39 mnemonic.
    Restore {
        /// File holding the mnemonic. Without it the phrase is read from stdin.
        #[arg(long, value_name = "FILE")]
        mnemonic_file: Option<PathBuf>,

        /// Which network the addresses belong to.
        #[arg(long, default_value = "devnet", value_name = "NAME")]
        network: String,

        /// Overwrite an existing keystore at this datadir.
        #[arg(long)]
        force: bool,

        #[command(flatten)]
        passphrase: PassphraseArgs,
    },

    /// Print a receive address.
    Address {
        /// Issue a fresh address instead of reprinting the current one.
        #[arg(long)]
        new: bool,

        #[command(flatten)]
        passphrase: PassphraseArgs,
    },

    /// Confirmed, immature and pending balance.
    Balance {
        #[command(flatten)]
        passphrase: PassphraseArgs,
    },

    /// Build, sign and broadcast a payment.
    Send {
        /// Recipient address.
        #[arg(long, value_name = "ADDR")]
        to: String,

        /// Amount in FRM, e.g. `1.5`.
        #[arg(long, value_name = "FRM")]
        amount: String,

        /// Fee rate in grains per 1000 bytes.
        #[arg(long, default_value_t = 1_000, value_name = "N")]
        fee_rate: u64,

        /// Build and sign but do not broadcast.
        #[arg(long)]
        dry_run: bool,

        #[command(flatten)]
        passphrase: PassphraseArgs,
    },

    /// The wallet's unspent outputs, as the node reports them.
    ListUnspent {
        #[command(flatten)]
        passphrase: PassphraseArgs,
    },

    /// Print the wallet's mnemonic. Treat the output as the wallet itself.
    DumpSeed {
        #[command(flatten)]
        passphrase: PassphraseArgs,
    },

    /// Print the 64-hex x-only public key of a key file.
    DumpPubkey {
        /// The key file: 64 hex characters, or a BIP-39 phrase.
        #[arg(long, value_name = "FILE")]
        key: PathBuf,

        /// Which network to interpret a mnemonic key file for.
        #[arg(long, default_value = "devnet", value_name = "NAME")]
        network: String,
    },
}

/// `chain-cli tx ...`
#[derive(Debug, Subcommand)]
pub enum TxCmd {
    /// Decode a transaction envelope locally, without a node.
    Decode {
        /// The transaction envelope, hex.
        #[arg(value_name = "HEX")]
        hex: String,
    },
    /// Broadcast a raw transaction envelope.
    Send {
        /// The transaction envelope, hex.
        #[arg(value_name = "HEX")]
        hex: String,
    },
    /// Fetch a transaction by id.
    Get {
        /// The transaction id, 64 hex characters.
        #[arg(value_name = "TXID")]
        txid: String,

        /// Return the raw envelope hex instead of the decoded form.
        #[arg(long)]
        raw: bool,
    },
}

/// `chain-cli block ...`
#[derive(Debug, Subcommand)]
pub enum BlockCmd {
    /// Fetch a block by hash or height.
    Get {
        /// A 64-hex block hash, or a decimal height.
        #[arg(value_name = "HASH_OR_HEIGHT")]
        target: String,

        /// 0 = hex, 1 = header plus txids, 2 = fully decoded.
        #[arg(long, default_value_t = 1, value_name = "N")]
        verbosity: u8,
    },
    /// The active-chain block hash at a height.
    Hash {
        /// The height.
        #[arg(value_name = "HEIGHT")]
        height: u64,
    },
    /// The current tip hash and height.
    Tip,
}

/// `chain-cli script ...`
#[derive(Debug, Subcommand)]
pub enum ScriptCmd {
    /// Run a script through the virtual machine.
    ///
    /// Two modes. With `--script-pubkey` the full consensus path runs —
    /// push-only `script_sig`, P2SH, and the clean-stack rule — which is what
    /// a node does. With `--script` alone a single script is evaluated over an
    /// optional starting stack, which is what a template author wants.
    Eval(Box<ScriptEvalArgs>),

    /// Disassemble a script to one instruction per line.
    Disassemble {
        /// The script, hex.
        #[arg(value_name = "HEX")]
        hex: String,
    },

    /// Build `OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`.
    BuildP2pkh {
        /// A 64-hex x-only public key to hash.
        #[arg(long, value_name = "HEX", conflicts_with_all = ["hash160", "address"])]
        pubkey: Option<String>,

        /// A 40-hex `hash160` payload, used directly.
        #[arg(long, value_name = "HEX", conflicts_with = "address")]
        hash160: Option<String>,

        /// A bech32m address to take the payload from.
        #[arg(long, value_name = "ADDR")]
        address: Option<String>,
    },

    /// Build a bare `k`-of-`n` multisig script.
    BuildMultisig {
        /// Signatures required.
        #[arg(short = 'k', long = "threshold", value_name = "K")]
        threshold: u8,

        /// A 64-hex x-only public key. Repeat for each key, in order.
        #[arg(long = "pubkey", value_name = "HEX", required = true, num_args = 1..)]
        pubkeys: Vec<String>,
    },

    /// Build a hash-timelocked contract.
    BuildHtlc {
        /// The 40-hex `hash160` of the preimage.
        #[arg(long, value_name = "HEX")]
        hash: String,

        /// The receiver's 40-hex public-key hash.
        #[arg(long, value_name = "HEX")]
        receiver: String,

        /// Absolute locktime after which the refund branch opens.
        #[arg(long, value_name = "N")]
        timeout: u32,

        /// The refunder's 40-hex public-key hash.
        #[arg(long, value_name = "HEX")]
        refund: String,
    },
}

/// Arguments to `chain-cli script eval`.
#[derive(Debug, Args)]
pub struct ScriptEvalArgs {
    /// The script to evaluate, hex. Mutually exclusive with `--script-pubkey`.
    #[arg(long, value_name = "HEX", conflicts_with = "script_pubkey")]
    pub script: Option<String>,

    /// The locking script of the output being spent, hex.
    #[arg(long, value_name = "HEX", requires = "script_sig")]
    pub script_pubkey: Option<String>,

    /// The unlocking script, hex. Required with `--script-pubkey`.
    #[arg(long, value_name = "HEX")]
    pub script_sig: Option<String>,

    /// A starting stack element, bottom first. Repeatable. `--script` only.
    #[arg(long = "stack", value_name = "HEX", num_args = 0..)]
    pub stack: Vec<String>,

    /// The spending transaction envelope, hex. Needed for any signature check.
    #[arg(long, value_name = "HEX")]
    pub tx: Option<String>,

    /// Which input of `--tx` is being unlocked.
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub input_index: usize,

    /// The value of the output being spent, in FRM. Committed to by the sighash.
    #[arg(long, default_value = "0", value_name = "FRM")]
    pub input_value: String,

    /// Block height the spend is evaluated at, for `OP_CHECKLOCKTIMEVERIFY`.
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub height: u64,

    /// Median time past in seconds, for a timestamp-flavoured CLTV.
    #[arg(long, default_value_t = 0, value_name = "SECONDS")]
    pub mtp: u64,

    /// Which network's chain id the signatures must commit to.
    #[arg(long, default_value = "devnet", value_name = "NAME")]
    pub network: String,
}

/// `chain-cli chain ...`
#[derive(Debug, Subcommand)]
pub enum ChainCmd {
    /// Chain identity, tip, difficulty, engine and finality.
    Info,
    /// Connected peers.
    Peers,
    /// The UTXO-set Merkle root.
    Stateroot {
        /// Height to report. Only the tip is retained, so this must be the tip.
        #[arg(long, value_name = "N")]
        height: Option<u64>,
    },
    /// Rebuild the transaction and address reverse index from block bodies.
    ///
    /// Local and offline: it opens the store in `--datadir` directly, so the
    /// node must be stopped first.
    Reindex {
        /// Report what would be done and change nothing.
        #[arg(long)]
        dry_run: bool,

        /// Which network's parameters the store belongs to.
        #[arg(long, default_value = "devnet", value_name = "NAME")]
        network: String,
    },
}

/// `chain-cli genesis ...`
#[derive(Debug, Subcommand)]
pub enum GenesisCmd {
    /// Grind a genesis block for a new network.
    ///
    /// Prints `nonce=<n> hash=<hex>` as the last line of stdout, which is the
    /// shape CONTRACT §13.1 fixes and `RUNNING.md` §4 tells operators to copy
    /// into their `ChainParams`.
    Mine {
        /// Which network's parameters to grind against.
        #[arg(long, default_value = "devnet", value_name = "NAME")]
        network: String,

        /// The coinbase message. Defaults to this network's standard message.
        #[arg(long, value_name = "TEXT")]
        message: Option<String>,

        /// Genesis timestamp in Unix milliseconds.
        #[arg(long, value_name = "MS")]
        timestamp: Option<u64>,

        /// Override the compact target the header must meet.
        #[arg(long, value_name = "HEX_OR_DEC")]
        bits: Option<String>,

        /// First nonce to try.
        #[arg(long, default_value_t = 0, value_name = "N")]
        start_nonce: u64,

        /// Give up after this many nonces.
        #[arg(long, default_value_t = 1 << 32, value_name = "N")]
        max_tries: u64,
    },
}

/// `chain-cli faucet ...`
#[derive(Debug, Subcommand)]
pub enum FaucetCmd {
    /// Ask a node's faucet for coins.
    Request {
        /// Where to send them. Defaults to this wallet's current address.
        #[arg(long, value_name = "ADDR")]
        address: Option<String>,

        /// The explorer endpoint that serves `/api/faucet`.
        #[arg(long, default_value = "http://127.0.0.1:8665", value_name = "URL")]
        explorer: String,

        #[command(flatten)]
        passphrase: PassphraseArgs,
    },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn the_command_tree_is_internally_consistent() {
        ChainCli::command().debug_assert();
    }

    #[test]
    fn the_globals_are_accepted_before_the_subcommand() {
        let cli = ChainCli::try_parse_from([
            "chain-cli",
            "--datadir",
            "D:/devnet/node1",
            "--rpc",
            "http://127.0.0.1:8646",
            "wallet",
            "address",
        ])
        .unwrap();
        assert_eq!(cli.datadir.as_deref(), Some(std::path::Path::new("D:/devnet/node1")));
        assert_eq!(cli.rpc.as_deref(), Some("http://127.0.0.1:8646"));
        assert!(matches!(cli.command, Command::Wallet(WalletCmd::Address { new: false, .. })));
    }

    #[test]
    fn the_globals_are_also_accepted_after_the_subcommand() {
        let cli =
            ChainCli::try_parse_from(["chain-cli", "chain", "info", "--json"]).unwrap();
        assert!(cli.json);
    }

    #[test]
    fn there_is_no_passphrase_flag_anywhere() {
        // A passphrase in the argument vector is readable by every other
        // process on the machine. If this ever parses, that protection is gone.
        let attempt = ChainCli::try_parse_from([
            "chain-cli",
            "wallet",
            "new",
            "--passphrase",
            "hunter2",
        ]);
        assert!(attempt.is_err());
    }

    #[test]
    fn wallet_new_takes_an_output_file() {
        let cli =
            ChainCli::try_parse_from(["chain-cli", "wallet", "new", "--output", "v.key"]).unwrap();
        match cli.command {
            Command::Wallet(WalletCmd::New { output, words, .. }) => {
                assert_eq!(output.as_deref(), Some(std::path::Path::new("v.key")));
                assert_eq!(words, 12);
            }
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn dump_pubkey_requires_a_key_file() {
        assert!(ChainCli::try_parse_from(["chain-cli", "wallet", "dump-pubkey"]).is_err());
        assert!(
            ChainCli::try_parse_from(["chain-cli", "wallet", "dump-pubkey", "--key", "v.key"])
                .is_ok()
        );
    }

    #[test]
    fn script_eval_refuses_both_modes_at_once() {
        let attempt = ChainCli::try_parse_from([
            "chain-cli",
            "script",
            "eval",
            "--script",
            "51",
            "--script-pubkey",
            "51",
            "--script-sig",
            "00",
        ]);
        assert!(attempt.is_err());
    }

    #[test]
    fn build_multisig_takes_repeated_pubkeys() {
        let cli = ChainCli::try_parse_from([
            "chain-cli",
            "script",
            "build-multisig",
            "-k",
            "2",
            "--pubkey",
            "aa",
            "--pubkey",
            "bb",
            "--pubkey",
            "cc",
        ])
        .unwrap();
        match cli.command {
            Command::Script(ScriptCmd::BuildMultisig { threshold, pubkeys }) => {
                assert_eq!(threshold, 2);
                assert_eq!(pubkeys, vec!["aa", "bb", "cc"]);
            }
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn genesis_mine_takes_the_three_documented_flags() {
        let cli = ChainCli::try_parse_from([
            "chain-cli",
            "genesis",
            "mine",
            "--network",
            "mainnet",
            "--message",
            "hello",
            "--timestamp",
            "1757203200000",
        ])
        .unwrap();
        match cli.command {
            Command::Genesis(GenesisCmd::Mine { network, message, timestamp, .. }) => {
                assert_eq!(network, "mainnet");
                assert_eq!(message.as_deref(), Some("hello"));
                assert_eq!(timestamp, Some(1_757_203_200_000));
            }
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn wallet_send_matches_the_devnet_invocation() {
        // devnet/ci-e2e.sh: wallet send --to "$addr" --amount 1.0
        let cli = ChainCli::try_parse_from([
            "chain-cli",
            "--rpc",
            "http://127.0.0.1:8645",
            "wallet",
            "send",
            "--to",
            "rfer1qexample",
            "--amount",
            "1.0",
        ])
        .unwrap();
        match cli.command {
            Command::Wallet(WalletCmd::Send { to, amount, fee_rate, .. }) => {
                assert_eq!(to, "rfer1qexample");
                assert_eq!(amount, "1.0");
                assert_eq!(fee_rate, 1_000);
            }
            other => panic!("parsed as {other:?}"),
        }
    }
}
