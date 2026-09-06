# Ferrum — Normative Build Contract v1

> **This file is the single source of truth.** Every crate is implemented strictly against it.
> If an implementation and this document disagree, the document wins and the implementation is a bug.
> Prose specs (`SPEC.md`, `ENCODING.md`, `RUNNING.md`) are derived from this file and must never
> contradict it.

Chain name **Ferrum**. Ticker **FRM**. Base unit **grain**. `1 FRM = 100_000_000 grain`.

---

## 0. Global invariants

1. **No floating point anywhere.** `f32`/`f64` are denied by `clippy.toml`. Difficulty, fees and
   subsidy are integer-only.
2. **No non-determinism in the state-transition path.** No `SystemTime::now`, no `Instant::now`,
   no `rand`, no `HashMap`/`HashSet` iteration, no I/O, no thread scheduling effects. Wall-clock
   time enters only through `BlockCtx`, which is supplied by the caller.
3. **All integers are little-endian on the wire** (Borsh's convention), with exactly one exception:
   **database keys are big-endian** so that bytewise lexicographic ordering equals numeric ordering.
4. **`unsafe` is forbidden** workspace-wide (`unsafe_code = "forbid"`).
5. **Consensus arithmetic is checked.** In `chain`, `script` and `consensus`, every `+ - *` on a
   consensus quantity uses `checked_*` / `saturating_*` and maps overflow to a typed error.
   Those three crates carry `#![warn(clippy::arithmetic_side_effects)]` and CI denies it.
6. **Dependency direction is enforced by CI.** `consensus` may depend on `types` and `crypto` only.
   It must never depend on `chain`, `storage`, `mempool`, `p2p`, `rpc`, `wallet` or `node`.
   That single rule is what makes the PoW→BFT swap a config change instead of a rewrite.

---

## 1. Frozen domain-separation tags

Hashing is BLAKE3 in *derive-key* mode: `blake3::Hasher::new_derive_key(TAG)` then `update(data)`.
The context string is the domain tag. **This list is frozen. Adding a tag is allowed; changing or
removing one is a hard fork.** A test asserts all tags are pairwise distinct and that
`tagged_hash(a, x) != tagged_hash(b, x)` for every pair.

| Constant | Context string | Used for |
|---|---|---|
| `TAG_TXID`          | `ferrum.v1.txid`          | transaction id = H(borsh(tx)) |
| `TAG_SIGHASH`       | `ferrum.v1.sighash`       | signature preimage digest |
| `TAG_HEADER`        | `ferrum.v1.header`        | block hash = H(borsh(header)) |
| `TAG_MERKLE_LEAF`   | `ferrum.v1.merkle.leaf`   | Merkle leaf (RFC 6962 shape) |
| `TAG_MERKLE_NODE`   | `ferrum.v1.merkle.node`   | Merkle internal node |
| `TAG_ADDRESS`       | `ferrum.v1.address`       | address payload commitment |
| `TAG_SCRIPT`        | `ferrum.v1.script`        | script hash for P2SH |
| `TAG_STATE_ROOT`    | `ferrum.v1.state.root`    | UTXO-set Merkle root |
| `TAG_UNDO`          | `ferrum.v1.undo`          | undo-record digest |
| `TAG_BFT_PROPOSAL`  | `ferrum.v1.bft.proposal`  | BFT proposal signing |
| `TAG_BFT_PREVOTE`   | `ferrum.v1.bft.prevote`   | BFT prevote signing |
| `TAG_BFT_PRECOMMIT` | `ferrum.v1.bft.precommit` | BFT precommit signing |
| `TAG_P2P_MSGID`     | `ferrum.v1.p2p.msgid`     | gossipsub content-addressed message id |
| `TAG_GENESIS`       | `ferrum.v1.genesis`       | genesis parameter commitment |
| `TAG_HD_SEED`       | `ferrum.v1.hd.seed`       | BIP-32 master key derivation |

`hash160(x) = ripemd160(sha256(x))` — used only for P2PKH payloads, for 20-byte addresses.
`hash256(x) = tagged_hash(TAG_SCRIPT, x)` for script hashes.

---

## 2. Canonical encoding

**Borsh 1.x** with `#[derive(BorshSerialize, BorshDeserialize)]`. Borsh guarantees a bijective
object↔bytes mapping, which is the property we need; it is not hand-rolled.

Rules that are consensus-critical and must be tested:

- `Vec<T>` is `u32 LE length || elements`.
- Fixed arrays (`[u8; 32]`) carry no length prefix.
- Newtypes over a single field encode exactly as that field.
- **Enums** are `u8 discriminant || variant fields`.
- `Option<T>` is `0u8` or `1u8 || T`.
- **Decoding must reject trailing bytes.** Always use `borsh::from_slice`, never a reader that
  tolerates a suffix. A trailing-byte tolerance is a txid-malleability bug.
- **Round-trip is bidirectional:** `decode(encode(v)) == v` *and* `encode(decode(b)) == b` for every
  `b` that decodes. Both directions are proptested.

### 2.1 Typed transaction envelope

Every transaction on the wire and in a block is:

```
tx_envelope := type_byte:u8 || borsh(Transaction)
```

- `type_byte` ∈ `[0x00, 0x7f]`. `0x00` = `Standard` (the only type in v1).
- `0x80..=0xfe` are reserved for future types and **must be rejected** in v1.
- `0xff` is permanently reserved as an escape/extension marker and must always be rejected.

`Txid = tagged_hash(TAG_TXID, tx_envelope)`. The type byte is inside the txid preimage.

### 2.2 Header encoding — exactly 88 bytes

| Offset | Size | Field | Type |
|---|---|---|---|
| 0  | 4  | `version`      | `u32` LE |
| 4  | 32 | `prev_hash`    | `[u8;32]` |
| 36 | 32 | `merkle_root`  | `[u8;32]` |
| 68 | 8  | `timestamp_ms` | `u64` LE (Unix milliseconds) |
| 76 | 4  | `bits`         | `u32` LE (compact target) |
| 80 | 8  | `nonce`        | `u64` LE |

`BlockHash = tagged_hash(TAG_HEADER, header_bytes)`. A unit test asserts
`borsh::to_vec(&header).len() == 88`.

`timestamp_ms` is milliseconds, not seconds: Bitcoin's `u32` seconds field overflows in 2106.

### 2.3 Block encoding

```rust
Block { header: BlockHeader, txs: Vec<Transaction>, seal: BlockSeal }
BlockSeal { engine: u8, data: Vec<u8> }   // engine 0 = PoW (data empty), 1 = BFT (data = borsh(BftCommit))
```

**The seal is deliberately outside the header and outside `merkle_root`.** A BFT commit certificate
is formed *after* the header exists and cannot commit to itself; keeping it out of the header means
the block hash is identical no matter which `2f+1` subset of signatures a node collected.

### 2.4 Hex display

`Hash32` displays as lowercase hex of the bytes **in natural order**. Ferrum does *not* reverse
bytes for display; Bitcoin's reversal is a historical accident and reproducing it costs debugging
hours forever. `FromStr` accepts 64 hex chars, with or without a `0x` prefix, case-insensitive.

---

## 3. `ferrum-types` — the foundation (depends on nothing but borsh/serde/hex/thiserror)

```rust
// ---- primitives ----
pub struct Hash32([u8; 32]);                 // Copy, Ord, Hash, Borsh, Serde(hex string), Display=hex
impl Hash32 {
    pub const ZERO: Hash32;
    pub const fn from_bytes(b: [u8; 32]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; 32];
    pub fn to_hex(&self) -> String;
    pub fn from_hex(s: &str) -> Result<Self, TypeError>;
}

pub struct BlockHash(pub Hash32);            // newtype, same derives + Display
pub struct Txid(pub Hash32);                 // newtype, same derives + Display

/// Monetary amount in grains. Arithmetic is checked; there is no `impl Add`.
pub struct Amount(u64);
impl Amount {
    pub const ZERO: Amount;
    pub const MAX_MONEY: Amount;             // 21_000_000 * COIN
    pub const fn from_grains(v: u64) -> Self;
    pub const fn to_grains(self) -> u64;
    pub fn from_frm_str(s: &str) -> Result<Self, TypeError>;   // "12.34567890" -> grains, integer-only parse
    pub fn to_frm_string(self) -> String;                      // "12.34567890"
    pub fn checked_add(self, o: Amount) -> Option<Amount>;
    pub fn checked_sub(self, o: Amount) -> Option<Amount>;
    pub fn checked_mul_u64(self, k: u64) -> Option<Amount>;
    pub fn is_valid_money(self) -> bool;     // 0 <= v <= MAX_MONEY
}
pub const COIN: u64 = 100_000_000;

pub struct ChainId(pub u32);                 // 1 = mainnet, 2 = testnet, 3 = devnet
pub struct CompactTarget(pub u32);           // see §6.1

// ---- transaction model ----
pub struct OutPoint { pub txid: Txid, pub vout: u32 }
impl OutPoint { pub const NULL: OutPoint; pub fn is_null(&self) -> bool; }   // NULL = coinbase input

pub struct Script(Vec<u8>);
impl Script {
    pub fn new(v: Vec<u8>) -> Self;
    pub fn as_bytes(&self) -> &[u8];
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn to_hex(&self) -> String;
    pub fn from_hex(s: &str) -> Result<Self, TypeError>;
}

pub struct TxIn  { pub prev_out: OutPoint, pub script_sig: Script, pub sequence: u32 }
pub struct TxOut { pub value: Amount, pub script_pubkey: Script }

pub struct Transaction {
    pub version: u32,
    pub inputs:  Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,           // < LOCKTIME_THRESHOLD => height, else Unix seconds
}
impl Transaction {
    pub fn is_coinbase(&self) -> bool;                 // exactly 1 input and it is OutPoint::NULL
    pub fn encode_envelope(&self) -> Vec<u8>;          // TX_TYPE_STANDARD || borsh(self)
    pub fn decode_envelope(b: &[u8]) -> Result<Self, TypeError>;
    pub fn total_output(&self) -> Option<Amount>;      // None on overflow / out-of-range
    pub fn serialized_size(&self) -> usize;            // size of encode_envelope()
}
pub const TX_TYPE_STANDARD: u8 = 0x00;
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

// ---- block model ----
pub struct BlockHeader {
    pub version: u32, pub prev_hash: BlockHash, pub merkle_root: Hash32,
    pub timestamp_ms: u64, pub bits: CompactTarget, pub nonce: u64,
}
pub const HEADER_SIZE: usize = 88;

pub struct BlockSeal { pub engine: u8, pub data: Vec<u8> }
impl BlockSeal { pub const POW: BlockSeal; pub const ENGINE_POW: u8 = 0; pub const ENGINE_BFT: u8 = 1; }

pub struct Block { pub header: BlockHeader, pub txs: Vec<Transaction>, pub seal: BlockSeal }
impl Block {
    pub fn coinbase(&self) -> Option<&Transaction>;    // txs[0] if it is_coinbase()
    pub fn serialized_size(&self) -> usize;
}

// ---- UTXO ----
/// One spendable output plus the context needed to validate and to undo.
pub struct Coin { pub value: Amount, pub script_pubkey: Script, pub height: u64, pub is_coinbase: bool }

// ---- chain parameters ----
pub struct ChainParams {
    pub network: Network,                 // Mainnet | Testnet | Devnet
    pub chain_id: ChainId,
    pub bech32_hrp: &'static str,         // "fer" | "tfer" | "rfer"
    pub target_spacing_ms: u64,           // 120_000
    pub asert_halflife_s: i64,            // 7200
    pub pow_limit: [u8; 32],              // big-endian max target
    pub initial_subsidy: Amount,          // 50 FRM
    pub halving_interval: u64,            // 210_000 blocks
    pub coinbase_maturity: u64,           // 100 blocks
    pub max_block_size: usize,            // 1_000_000 bytes
    pub max_future_block_time_ms: u64,    // 7_200_000 (2 h)
    pub median_time_span: usize,          // 11
    pub min_relay_fee_per_kb: Amount,     // 1_000 grains
    pub genesis_timestamp_ms: u64,
    pub genesis_bits: CompactTarget,
    pub genesis_nonce: u64,
    pub bft_activation_height: Option<u64>,   // None until the M10 fork is scheduled
    pub bft_validators: Vec<ValidatorId>,     // empty for PoW-only networks
}
impl ChainParams {
    pub fn mainnet() -> Self; pub fn testnet() -> Self; pub fn devnet() -> Self;
    pub fn by_name(s: &str) -> Result<Self, TypeError>;
    pub fn block_subsidy(&self, height: u64) -> Amount;   // halves every halving_interval; 0 after 64 halvings
    pub fn engine_at(&self, height: u64) -> u8;           // ENGINE_POW / ENGINE_BFT, from bft_activation_height
}

pub struct ValidatorId(pub [u8; 32]);     // x-only BIP-340 public key

pub enum Network { Mainnet, Testnet, Devnet }
```

`Amount` deliberately has **no** `Add`/`Sub` impls. Every monetary operation is a `checked_*` call
whose `None` becomes a typed error. This is the cheapest possible defence against an inflation bug.

---

## 4. `ferrum-crypto`

```rust
// ---- tagged hashing ----
pub struct Tag(pub &'static str);
pub const TAG_TXID: Tag; /* ... all tags from §1 ... */
pub fn tagged_hash(tag: Tag, data: &[u8]) -> Hash32;
pub fn tagged_hasher(tag: Tag) -> blake3::Hasher;    // cached derive-key hasher, cloned
pub fn hash160(data: &[u8]) -> [u8; 20];             // ripemd160(sha256(x))
pub fn sha256(data: &[u8]) -> [u8; 32];

// ---- BIP-340 Schnorr over secp256k1 (k256) ----
pub struct SecretKey(/* zeroize on drop */);
pub struct PublicKey([u8; 32]);          // x-only, 32 bytes
pub struct Signature([u8; 64]);

impl SecretKey {
    pub fn from_bytes(b: &[u8; 32]) -> Result<Self, CryptoError>;
    pub fn to_bytes(&self) -> [u8; 32];             // callers must zeroize
    pub fn public_key(&self) -> PublicKey;
    pub fn sign(&self, msg: &Hash32, aux: &[u8; 32]) -> Signature;   // BIP-340, deterministic given aux
    pub fn sign_deterministic(&self, msg: &Hash32) -> Signature;     // aux = [0u8;32]; used everywhere in tests
}
impl PublicKey {
    pub fn from_bytes(b: &[u8; 32]) -> Result<Self, CryptoError>;    // must be a valid x-only point
    pub fn as_bytes(&self) -> &[u8; 32];
    pub fn verify(&self, msg: &Hash32, sig: &Signature) -> Result<(), CryptoError>;
}
pub fn verify_batch(items: &[(PublicKey, Hash32, Signature)]) -> Result<(), CryptoError>;

// ---- Merkle (RFC 6962 shape; CVE-2012-2459 immune) ----
/// leaf  = tagged_hash(TAG_MERKLE_LEAF, data)
/// node  = tagged_hash(TAG_MERKLE_NODE, left || right)
/// An odd node at any level is **promoted** to the next level unchanged. It is NEVER duplicated.
/// Empty input yields Hash32::ZERO.
pub fn merkle_root(leaves: &[Hash32]) -> Hash32;
pub fn merkle_root_of_leaf_data<'a>(items: impl Iterator<Item = &'a [u8]>) -> Hash32;
pub struct MerkleProof { pub index: usize, pub siblings: Vec<(bool, Hash32)> }  // bool = sibling is on the right
pub fn merkle_proof(leaves: &[Hash32], index: usize) -> Option<MerkleProof>;
pub fn merkle_verify(root: &Hash32, leaf: &Hash32, proof: &MerkleProof) -> bool;

// ---- BIP-39 / BIP-32 ----
pub struct Mnemonic(/* zeroizing */);
impl Mnemonic {
    pub fn generate(words: usize, rng: &mut impl rand_core::CryptoRngCore) -> Result<Self, CryptoError>; // 12|15|18|21|24
    pub fn from_phrase(s: &str) -> Result<Self, CryptoError>;   // NFKD-normalised, checksum-verified
    pub fn phrase(&self) -> &str;
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64];        // PBKDF2-HMAC-SHA512, 2048 rounds
}
pub struct ExtendedKey { /* key + chain_code + depth + parent_fpr + child_number */ }
impl ExtendedKey {
    pub fn master_from_seed(seed: &[u8]) -> Result<Self, CryptoError>;   // HMAC-SHA512 "Ferrum seed"
    pub fn derive_child(&self, index: ChildNumber) -> Result<Self, CryptoError>;
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, CryptoError>;
    pub fn secret_key(&self) -> SecretKey;
    pub fn public_key(&self) -> PublicKey;
}
pub struct ChildNumber(u32);   // hardened when bit 31 is set
pub struct DerivationPath(Vec<ChildNumber>);   // FromStr: "m/44'/7767'/0'/0/0"
pub const COIN_TYPE: u32 = 7767;               // Ferrum SLIP-44-style coin type (self-assigned)

// ---- addresses (bech32m) ----
pub enum AddressPayload { PubKeyHash([u8; 20]), ScriptHash([u8; 32]) }
pub struct Address { pub network: Network, pub version: u8, pub payload: AddressPayload }
impl Address {
    pub fn p2pkh(network: Network, pk: &PublicKey) -> Self;         // version 0, hash160(x_only_pk)
    pub fn p2sh(network: Network, script: &Script) -> Self;         // version 1, tagged_hash(TAG_SCRIPT, script)
    pub fn encode(&self) -> String;                                 // bech32m, HRP from network
    pub fn decode(s: &str) -> Result<Self, CryptoError>;            // rejects wrong HRP, bad checksum, unknown version
    pub fn script_pubkey(&self) -> Script;                          // the canonical locking script
}
```

**BIP-340 conformance:** the crate must include the official BIP-340 test vectors (all 19, including
the invalid-signature cases) as a table-driven test. `k256`'s `schnorr` feature provides the
primitive; do not hand-roll the algorithm.

**CVE-2012-2459 regression test (mandatory):** build a tree from `n` leaves and a second tree from
those leaves with the final one duplicated; assert the roots differ. This is the exact bug that let
an attacker make a valid block look invalid in Bitcoin 0.6.

---

## 5. `ferrum-script` — the VM

### 5.1 Hard limits (present from the first commit; never retrofitted)

| Limit | Value |
|---|---|
| `MAX_SCRIPT_SIZE` | 1_000 bytes (each of `script_sig`, `script_pubkey`, redeem script) |
| `MAX_STACK_SIZE` | 100 (stack + altstack combined) |
| `MAX_ELEMENT_SIZE` | 520 bytes |
| `MAX_OPS` | 201 non-push opcodes per script |
| `MAX_PUBKEYS_PER_MULTISIG` | 20 |
| `MAX_NUM_SIZE` | 4 bytes for arithmetic operands (values are i32-ranged, held as i64) |
| Loops | none — there is no jump-backwards opcode |

### 5.2 Opcodes

```
0x00 OP_0                     push empty
0x01..=0x4b                   direct push of N bytes
0x4c OP_PUSHDATA1  0x4d OP_PUSHDATA2         (OP_PUSHDATA4 is NOT defined: MAX_SCRIPT_SIZE is 1000)
0x4f OP_1NEGATE
0x51..=0x60 OP_1..OP_16
0x61 OP_NOP
0x63 OP_IF   0x64 OP_NOTIF   0x67 OP_ELSE   0x68 OP_ENDIF
0x69 OP_VERIFY               0x6a OP_RETURN
0x6b OP_TOALTSTACK           0x6c OP_FROMALTSTACK
0x73 OP_IFDUP  0x74 OP_DEPTH  0x75 OP_DROP  0x76 OP_DUP  0x77 OP_NIP  0x78 OP_OVER
0x7c OP_SWAP   0x7d OP_TUCK   0x79 OP_PICK   0x7a OP_ROLL   0x7b OP_ROT   0x72 OP_2DUP
0x82 OP_SIZE
0x87 OP_EQUAL  0x88 OP_EQUALVERIFY
0x8b OP_1ADD   0x8c OP_1SUB   0x8f OP_NEGATE  0x90 OP_ABS  0x91 OP_NOT  0x92 OP_0NOTEQUAL
0x93 OP_ADD    0x94 OP_SUB
0x9a OP_BOOLAND 0x9b OP_BOOLOR 0x9c OP_NUMEQUAL 0x9d OP_NUMEQUALVERIFY 0x9e OP_NUMNOTEQUAL
0x9f OP_LESSTHAN 0xa0 OP_GREATERTHAN 0xa1 OP_LESSTHANOREQUAL 0xa2 OP_GREATERTHANOREQUAL
0xa3 OP_MIN 0xa4 OP_MAX 0xa5 OP_WITHIN
0xa6 OP_RIPEMD160 0xa7 OP_SHA256 0xa9 OP_HASH160 0xaa OP_HASH256
0xac OP_CHECKSIG 0xad OP_CHECKSIGVERIFY 0xae OP_CHECKMULTISIG 0xaf OP_CHECKMULTISIGVERIFY
0xb1 OP_CHECKLOCKTIMEVERIFY   0xb2 OP_CHECKSEQUENCEVERIFY
```

Every other byte is **`OP_INVALID`: encountering it fails the script**, including inside an untaken
`OP_IF` branch (unlike Bitcoin, whose `OP_NOP1..10` are soft-fork hooks; Ferrum has none).
Disabled-by-existence opcodes are not a concept here — the table above is exhaustive.

`OP_CHECKMULTISIG` does **not** have Bitcoin's off-by-one dummy-element bug. It pops exactly
`n`, the pubkeys, `k`, and the `k` signatures. Signature/pubkey matching is in order.

### 5.3 Number encoding

Minimally-encoded, sign-magnitude little-endian (Bitcoin's `CScriptNum` rules), max 4 bytes for
arithmetic inputs. Non-minimal encodings are rejected wherever a number is *read*.
Booleans: empty vector, `0x00`, `0x80` and any all-zero-with-sign-bit vector are false; everything
else is true. `OP_IF`/`OP_NOTIF` require a **minimally-encoded** `{}`/`{0x01}` condition operand.

### 5.4 Execution model

```rust
pub struct ScriptLimits { /* the table in §5.1, so tests can tighten them */ }
impl Default for ScriptLimits { /* consensus values */ }

pub struct ExecCtx<'a> {
    pub chain_id: ChainId,
    pub tx: &'a Transaction,
    pub input_index: usize,
    pub input_value: Amount,
    pub block_height: u64,
    pub block_mtp_s: u64,          // median time past, seconds — for CLTV against a timestamp
    pub limits: ScriptLimits,
}

pub struct ExecStats { pub ops: u32, pub max_stack: usize, pub sig_checks: u32 }

/// Runs script_sig, then script_pubkey over the resulting stack, then (if the
/// script_pubkey matches the P2SH template) the redeem script.
/// `script_sig` MUST be push-only — that is a **consensus** rule here, not a policy rule.
pub fn verify(
    script_sig: &Script, script_pubkey: &Script, ctx: &ExecCtx,
) -> Result<ExecStats, ScriptError>;

/// Standalone evaluation for `chain-cli script-eval` and for tests.
pub fn eval(script: &Script, initial: Vec<Vec<u8>>, ctx: &ExecCtx) -> Result<Stack, ScriptError>;

pub fn is_push_only(s: &Script) -> bool;
pub fn parse(s: &Script) -> Result<Vec<Instruction>, ScriptError>;   // full disassembly
pub fn disassemble(s: &Script) -> String;                            // human-readable, for the CLI
```

Success = script_pubkey leaves **exactly one** element on the stack and it is true. A leftover
stack of size ≠ 1 is a failure (Bitcoin's "clean stack" rule, made mandatory from day one).

**The interpreter must never panic on any input.** A `cargo-fuzz` target asserts this.

### 5.5 Sighash — BIP-143 shape, over the frozen preimage below

```
sighash_preimage :=
    chain_id           : u32  LE
 || tx_version         : u32  LE
 || hash_prevouts      : 32       // tagged_hash(TAG_SIGHASH, concat(borsh(outpoint) for all inputs)), or 32 zero bytes if ANYONECANPAY
 || hash_sequences     : 32       // tagged_hash(TAG_SIGHASH, concat(u32 LE sequence)), or zeros if ANYONECANPAY | NONE | SINGLE
 || input_index        : u32  LE
 || outpoint           : 36       // borsh(OutPoint) of the input being signed
 || script_code_len    : u32  LE
 || script_code        : bytes    // script_pubkey being satisfied, or the redeem script for P2SH
 || input_value        : u64  LE  // ** the amount being spent — this is why legacy sighash was replaced **
 || input_sequence     : u32  LE
 || hash_outputs       : 32       // ALL: hash of all outputs; SINGLE: hash of output[input_index]; NONE: zeros
 || lock_time          : u32  LE
 || sighash_type       : u8

sighash := tagged_hash(TAG_SIGHASH, sighash_preimage)
```

`SigHashType`: `ALL = 0x01`, `NONE = 0x02`, `SINGLE = 0x03`, flag `ANYONECANPAY = 0x80`.
Any other value is invalid. `SINGLE` with `input_index >= outputs.len()` is an **error**, not
Bitcoin's `uint256(1)` bug.

A signature in `script_sig` is `64-byte Schnorr || 1-byte sighash_type` = 65 bytes. Exactly 65.

### 5.6 Standard templates

```rust
pub mod templates {
    pub fn p2pk(pk: &PublicKey) -> Script;                                 // <32B pk> OP_CHECKSIG
    pub fn p2pkh(pkh: &[u8; 20]) -> Script;                                // OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG
    pub fn p2sh(script_hash: &Hash32) -> Script;                           // OP_HASH256 <32B> OP_EQUAL
    pub fn multisig(k: u8, pks: &[PublicKey]) -> Result<Script, ScriptError>;
    pub fn cltv_p2pkh(locktime: u32, pkh: &[u8; 20]) -> Script;
    pub fn htlc(hash: &[u8; 20], receiver_pkh: &[u8;20], timeout: u32, refund_pkh: &[u8;20]) -> Script;
    pub fn op_return(data: &[u8]) -> Result<Script, ScriptError>;          // max 80 bytes payload
    pub fn classify(s: &Script) -> ScriptType;                             // for the explorer + wallet
}
pub enum ScriptType { P2PK, P2PKH, P2SH, Multisig{k:u8,n:u8}, Cltv, Htlc, OpReturn, NonStandard }
```

---

## 6. `ferrum-consensus`

### 6.1 Compact target ("bits")

Bitcoin's 32-bit float-free encoding: `0xEEMMMMMM`, `EE` = size in bytes, `MMMMMM` = 24-bit mantissa.

```rust
pub struct Target(pub U256);   // primitive_types::U256
pub fn compact_to_target(c: CompactTarget) -> Result<Target, ConsensusError>;
pub fn target_to_compact(t: Target) -> CompactTarget;
```

Rejected as invalid: the negative form (mantissa bit `0x00800000` set), a zero mantissa with a
non-zero exponent, and any value whose expansion overflows 256 bits. `target_to_compact` always
produces the canonical (non-negative, normalised) form, so
`target_to_compact(compact_to_target(c)) == c` for every canonical `c` — proptested.

### 6.2 Work

```rust
pub struct Work(pub U256);
/// work(h) = (!target / (target + 1)) + 1   — 256-bit integer division, no floats.
pub fn work_from_target(t: Target) -> Work;
```

Fork choice is by **cumulative work, never by height**. Ties are broken by (1) lower block hash,
so that all honest nodes converge deterministically, after (2) first-seen — first-seen is a local
tiebreak applied before the hash rule and is *not* consensus.

### 6.3 ASERT (`aserti3-2d`) — integer only, exactly this algorithm

Anchor: the block at height `ANCHOR_HEIGHT = 1` (the first block after genesis) with its own
`bits` and `timestamp_ms`. For the first `ANCHOR_HEIGHT` blocks, `next_bits = genesis_bits`.

```text
Given: anchor_target, anchor_time_s, anchor_height,
       parent_time_s (the timestamp of the parent of the block being created),
       parent_height, target_spacing_s, halflife_s.

time_diff   : i64 = parent_time_s - anchor_time_s
height_diff : i64 = parent_height - anchor_height
exponent    : i64 = ((time_diff - target_spacing_s * (height_diff + 1)) * 65536) / halflife_s
                    // truncating division toward zero, then corrected below

// split into integer shift and 16-bit fraction, with a floor-division correction so that
// `frac` is always in [0, 65536) even for negative exponents:
shifts : i64 = exponent >> 16              // arithmetic shift = floor division by 65536
frac   : u64 = (exponent & 0xffff) as u64

// cubic polynomial approximation of 2^(frac/65536), max relative error < 0.013%
factor : u64 = 65536 + ((195_766_423_245_049 * frac
                        + 971_821_376 * frac^2
                        + 5_127 * frac^3
                        + (1u128 << 47)) >> 48)

next_target : U256 = anchor_target * factor
if shifts < 0 { next_target >>= (-shifts) } else { next_target <<= shifts }
next_target >>= 16

if next_target == 0        { next_target = 1 }
if next_target > pow_limit { next_target = pow_limit }
return target_to_compact(next_target)
```

All intermediate products use `u128`/`U256`; `frac^3 * 5127` cannot overflow `u128`.
A left shift that would exceed 256 bits saturates to `pow_limit`.

An **independent Python reference implementation** lives at `testing/reference/asert.py` and CI
diffs it against the Rust implementation over 200_000 synthetic `(time_diff, height_diff)` pairs.

### 6.4 The engine seam

```rust
pub trait HeaderView: Send + Sync {
    fn params(&self) -> &ChainParams;
    fn header_by_hash(&self, h: &BlockHash) -> Option<BlockHeader>;
    fn header_at_height(&self, height: u64) -> Option<BlockHeader>;   // on the active chain
    fn height_of(&self, h: &BlockHash) -> Option<u64>;
    fn tip(&self) -> (BlockHash, u64);
    /// Median of the last `median_time_span` headers ending at `h`, in **seconds**.
    fn median_time_past(&self, h: &BlockHash) -> Option<u64>;
}

pub struct BlockTemplate {
    pub header: BlockHeader,          // merkle_root and bits already set; nonce/timestamp are the engine's
    pub txs: Vec<Transaction>,
    pub height: u64,
}

pub trait ConsensusEngine: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &'static str;
    fn engine_id(&self) -> u8;                       // BlockSeal::ENGINE_*

    /// Header-only checks: PoW target, timestamp bounds, version, difficulty transition.
    fn validate_header(&self, h: &BlockHeader, parent: &BlockHeader, view: &dyn HeaderView)
        -> Result<(), ConsensusError>;

    /// Whole-block seal checks. PoW: the seal must be empty. BFT: verify the 2f+1 commit.
    fn validate_seal(&self, block: &Block, view: &dyn HeaderView) -> Result<(), ConsensusError>;

    /// The difficulty/target for a child of `parent`.
    fn next_bits(&self, parent: &BlockHeader, view: &dyn HeaderView)
        -> Result<CompactTarget, ConsensusError>;

    /// Mine (PoW) or propose+collect votes (BFT). Returns `Ok(None)` when cancelled.
    fn seal(&self, tmpl: BlockTemplate, cancel: &AtomicBool) -> Result<Option<Block>, ConsensusError>;

    /// Fork-choice weight contributed by this header.
    fn work(&self, h: &BlockHeader) -> Work;

    /// `None` for PoW (nothing is ever final). `Some(h)` for BFT, above which reorgs are impossible.
    fn finalized_height(&self, view: &dyn HeaderView) -> Option<u64>;
}

pub struct PowEngine { params: ChainParams }
pub struct BftEngine { /* validator set, keypair, round state */ }

/// Chooses the engine for a height, honouring `params.bft_activation_height`.
/// This is the whole of the M10 hard fork: one dispatcher, two engines, no other code changes.
pub struct EngineRouter { pow: PowEngine, bft: Option<BftEngine>, params: ChainParams }
impl EngineRouter { pub fn engine_for_height(&self, height: u64) -> &dyn ConsensusEngine; }
```

### 6.5 BFT (M9) — Tendermint-shaped, permissioned

- Validator set is fixed in `ChainParams::bft_validators` (x-only BIP-340 keys), `n >= 4`,
  `f = (n - 1) / 3`, quorum `2f + 1`.
- Round: **propose → prevote → precommit → commit**, with round-robin proposer
  `proposer(height, round) = validators[(height + round) % n]`.
- Timeouts (`propose`, `prevote`, `precommit`) double each round: `base * 2^round`.
- Locking: a validator that precommits a block in round `r` is locked on it and may only prevote a
  different block if it sees a `2f+1` polka for that block at a round `> r`.
- `BftCommit { height: u64, round: u32, block_hash: BlockHash, signatures: Vec<(u16, Signature)> }`
  where `u16` is the validator index. Signed message =
  `tagged_hash(TAG_BFT_PRECOMMIT, borsh(VoteMsg{chain_id, height, round, block_hash}))`.
- **Safety over liveness.** With `n = 4`, killing one validator continues; killing two **halts**.
  Halting is the correct behaviour and the README says so.

---

## 7. `ferrum-storage`

`redb` 2.x. **Exactly one write transaction per block**, and the head pointer is written **last,
inside that same transaction**. Numeric keys are **big-endian**.

| Table | Key | Value |
|---|---|---|
| `blocks`   | `block_hash[32]` | `borsh(Block)` |
| `headers`  | `block_hash[32]` | `borsh(BlockIndexEntry)` |
| `height`   | `be_u64(height)` | `block_hash[32]`  — the **active** chain only |
| `utxo`     | `borsh(OutPoint)` (36 B) | `borsh(Coin)` |
| `undo`     | `block_hash[32]` | `borsh(UndoBlock)` |
| `meta`     | `&str` | raw bytes (`tip`, `chain_id`, `schema_version`, `engine`) |
| `tx_index`* | `txid[32]` | `borsh(TxLocation{block_hash, index})` |
| `addr_index`* | `addr_key[20 or 32] ‖ be_u64(height) ‖ be_u32(tx_idx)` | `txid[32]` |

`*` The last two are the explorer's reverse index. They are **not consensus state**; they are built
only when `StoreConfig::index_transactions` is on, and a node without them is fully valid.

```rust
pub struct BlockIndexEntry {
    pub header: BlockHeader, pub height: u64,
    pub total_work: [u8; 32],        // big-endian U256
    pub status: BlockStatus,         // HeaderOnly | HaveData | Valid | Invalid
    pub tx_count: u32, pub size: u32,
    pub seal_engine: u8,
}
pub struct UndoBlock { pub spent: Vec<UndoCoin> }        // in the exact order inputs were spent
pub struct UndoCoin  { pub out_point: OutPoint, pub coin: Coin }

pub trait StateView: Send + Sync {
    fn get_coin(&self, op: &OutPoint) -> Result<Option<Coin>, StorageError>;
    fn has_coin(&self, op: &OutPoint) -> Result<bool, StorageError>;
}

pub struct StateDiff {
    pub spent:   Vec<(OutPoint, Coin)>,   // becomes the undo record, in input order
    pub created: Vec<(OutPoint, Coin)>,
}
/// An in-memory overlay used while validating a block: reads fall through to the backing view.
pub struct OverlayView<'a> { /* base: &'a dyn StateView, cache: BTreeMap<OutPoint, Option<Coin>> */ }

pub struct Store { /* redb::Database */ }
impl Store {
    pub fn open(path: &Path, cfg: StoreConfig) -> Result<Self, StorageError>;
    pub fn open_in_memory(cfg: StoreConfig) -> Result<Self, StorageError>;

    // reads
    pub fn get_block(&self, h: &BlockHash) -> Result<Option<Block>, StorageError>;
    pub fn get_header(&self, h: &BlockHash) -> Result<Option<BlockIndexEntry>, StorageError>;
    pub fn hash_at_height(&self, height: u64) -> Result<Option<BlockHash>, StorageError>;
    pub fn tip(&self) -> Result<Option<(BlockHash, u64)>, StorageError>;
    pub fn get_coin(&self, op: &OutPoint) -> Result<Option<Coin>, StorageError>;
    pub fn utxo_count(&self) -> Result<u64, StorageError>;
    pub fn iter_utxos(&self) -> Result<impl Iterator<Item = Result<(OutPoint, Coin), StorageError>>, StorageError>;
    pub fn get_undo(&self, h: &BlockHash) -> Result<Option<UndoBlock>, StorageError>;
    pub fn tx_location(&self, txid: &Txid) -> Result<Option<TxLocation>, StorageError>;
    pub fn address_history(&self, key: &[u8], from_height: u64, limit: usize)
        -> Result<Vec<(u64, Txid)>, StorageError>;

    // writes — each is ONE redb write transaction
    pub fn store_header(&self, e: &BlockIndexEntry) -> Result<(), StorageError>;
    pub fn store_block_body(&self, h: &BlockHash, b: &Block) -> Result<(), StorageError>;
    /// Apply `diff`, write the undo record, extend `height`, and set `tip` — atomically, tip last.
    pub fn connect_block(&self, h: &BlockHash, height: u64, entry: &BlockIndexEntry,
                         diff: &StateDiff, block: &Block) -> Result<(), StorageError>;
    /// Reverse `connect_block` using the stored undo record. Byte-identical UTXO set guaranteed.
    pub fn disconnect_tip(&self) -> Result<BlockHash, StorageError>;

    /// Sorted binary Merkle over the whole UTXO set. Not consensus state; used by the
    /// determinism harness, the reference-executor differential and `getstateroot`.
    pub fn state_root(&self) -> Result<Hash32, StorageError>;
}
```

`state_root` leaves are `tagged_hash(TAG_STATE_ROOT, borsh(OutPoint) || borsh(Coin))`, taken in
ascending `borsh(OutPoint)` byte order, combined with the §4 Merkle rules.

**Async rule:** `redb` is synchronous. Every call from an `async fn` goes through
`tokio::task::spawn_blocking`. CI greps for direct `Store::` calls inside `async fn` bodies.

---

## 8. `ferrum-chain` — validation and the determinism seam

```rust
pub struct BlockCtx {
    pub height: u64,
    pub prev_header: BlockHeader,
    pub median_time_past_s: u64,
    pub params: ChainParams,
    pub engine_id: u8,
}

/// **The determinism seam.** A pure function of (pre-state, block, ctx). No clock, no RNG, no I/O.
pub fn apply_block(pre: &dyn StateView, block: &Block, ctx: &BlockCtx)
    -> Result<StateDiff, ValidationError>;

pub fn check_block_sanity(block: &Block, params: &ChainParams) -> Result<(), ValidationError>;
pub fn check_transaction_sanity(tx: &Transaction, params: &ChainParams) -> Result<(), ValidationError>;
pub fn compute_merkle_root(txs: &[Transaction]) -> Hash32;   // leaves = txid bytes
pub fn median_time_past(headers: &[BlockHeader]) -> u64;      // seconds; median of up to 11
```

### 8.1 Block validation rules, in the order they are checked

1. `block.serialized_size() <= params.max_block_size`.
2. `!block.txs.is_empty()` and `block.txs[0].is_coinbase()` and no other tx is a coinbase.
3. `compute_merkle_root(&block.txs) == header.merkle_root`.
4. No duplicate txid within the block.
5. Engine header checks (`ConsensusEngine::validate_header`): PoW target met; `bits` equals
   `next_bits(parent)`; `timestamp_ms > median_time_past(parent) * 1000`;
   `timestamp_ms <= now + max_future_block_time_ms` (this check lives in the **node**, not in
   `apply_block`, because it needs a clock — the seam stays pure).
6. `ConsensusEngine::validate_seal`.
7. For each non-coinbase tx, in order:
   - sanity: non-empty inputs and outputs; every `value.is_valid_money()`; sum of outputs valid;
     no duplicate input `OutPoint` within the tx.
   - every input resolves to an unspent `Coin` in the overlay (missing ⇒ `MissingInput`, which the
     caller may treat as "orphan" rather than "invalid").
   - coinbase maturity: `coin.is_coinbase` ⇒ `ctx.height >= coin.height + coinbase_maturity`.
   - `sum(inputs) >= sum(outputs)`, both `checked_*`, both `is_valid_money`.
   - final-ness: a tx with `lock_time != 0` is final only if
     `lock_time < LOCKTIME_THRESHOLD ? lock_time <= height : lock_time <= mtp_s`, unless every
     input has `sequence == u32::MAX`.
   - `script::verify` for every input, with `ExecCtx` filled from the resolved coin.
   - mark inputs spent in the overlay, add outputs.
8. Coinbase: exactly one input, `OutPoint::NULL`, `script_sig` between 2 and 100 bytes and
   **beginning with a minimally-encoded push of `ctx.height`** (BIP-34 style, so coinbase txids
   can never collide — this is the fix for CVE-2012-1909 / BIP-30).
   `coinbase_output_total <= block_subsidy(height) + total_fees`.
9. Every created output's `OutPoint` must not already exist in the UTXO set.

`ValidationError` is a `#[non_exhaustive]` enum with one variant per rule above, so tests can assert
the *exact* reason a block was rejected.

### 8.2 Chain manager

```rust
pub struct ChainManager { /* Store + EngineRouter + params + tip cache */ }
impl ChainManager {
    pub fn open(store: Arc<Store>, params: ChainParams, engines: Arc<EngineRouter>)
        -> Result<Self, ChainError>;
    pub fn init_genesis(&self) -> Result<BlockHash, ChainError>;   // idempotent
    pub fn tip(&self) -> (BlockHash, u64);
    pub fn total_work(&self, h: &BlockHash) -> Option<Work>;

    /// Full acceptance: store, validate, and reorganise to the best chain if this improves it.
    pub fn accept_block(&self, block: Block) -> Result<AcceptOutcome, ChainError>;
    pub fn accept_header(&self, header: BlockHeader) -> Result<(), ChainError>;

    /// Build a candidate block from the mempool for the given payout script.
    pub fn build_template(&self, payout: &Script, extra_nonce: u64, txs: Vec<Transaction>,
                          now_ms: u64) -> Result<BlockTemplate, ChainError>;

    pub fn locator(&self) -> Vec<BlockHash>;                       // exponential back-off locator
    pub fn find_fork_point(&self, locator: &[BlockHash]) -> Option<(BlockHash, u64)>;
    pub fn headers_from(&self, locator: &[BlockHash], max: usize) -> Vec<BlockHeader>;
    pub fn subscribe(&self) -> Receiver<ChainEvent>;               // NewTip { .. }, Reorg { .. }
}
pub enum AcceptOutcome { Extended(BlockHash), Reorged { from: BlockHash, to: BlockHash, disconnected: Vec<BlockHash>, connected: Vec<BlockHash> }, SideChain(BlockHash), Duplicate, Orphan }
```

### 8.3 Reorg

Given a candidate with strictly greater cumulative work: walk both branches to the common ancestor,
`disconnect_tip()` down to it, then connect forward. **If any connect fails, the whole reorg is
rolled back to the original tip and the candidate branch is marked `Invalid`.** Reorg depth is
capped by `finalized_height()` when the engine provides one.

Guaranteed property, asserted in CI: *disconnecting N blocks and reconnecting them yields a
byte-identical UTXO set and an identical `state_root`.*

---

## 9. `ferrum-mempool`

```rust
pub struct Mempool { /* BTreeMap<Txid, MempoolEntry> + fee index + spent-outpoint index + orphans */ }
pub struct MempoolEntry { pub tx: Transaction, pub fee: Amount, pub size: usize,
                          pub fee_rate: u64 /* grains per 1000 bytes */, pub added_height: u64 }
impl Mempool {
    pub fn new(cfg: MempoolConfig) -> Self;
    pub fn accept(&self, tx: Transaction, view: &dyn StateView, tip_height: u64, mtp_s: u64)
        -> Result<AcceptResult, MempoolError>;
    pub fn select_for_block(&self, max_bytes: usize, view: &dyn StateView, height: u64) -> Vec<Transaction>;
    pub fn remove_confirmed(&self, txs: &[Transaction]);
    /// On a reorg: re-add transactions from disconnected blocks, drop those now invalid, and
    /// evict anything that double-spends a newly connected block.
    pub fn reconcile_reorg(&self, disconnected: &[Block], connected: &[Block], view: &dyn StateView, height: u64);
    pub fn get(&self, id: &Txid) -> Option<MempoolEntry>;
    pub fn len(&self) -> usize;
    pub fn size_bytes(&self) -> usize;
}
pub struct MempoolConfig { pub max_bytes: usize /* 8 MiB */, pub max_orphans: usize /* 200 */,
                           pub min_fee_rate: u64, pub expiry_blocks: u64 /* 336 */ }
```

Policy: reject non-standard scripts, reject fee rate below `min_fee_rate`, reject if the tx spends
an output already spent by a mempool tx (no RBF in v1 — say so in the docs), evict lowest fee-rate
first when over `max_bytes`, and hold transactions with missing inputs in the orphan pool keyed by
the missing parent txid.

---

## 10. `ferrum-p2p`

libp2p **0.55**, `tokio` executor, transport = TCP + **Noise** + **Yamux**. `mplex` is never offered.

### 10.1 The five gossipsub defaults that must be overridden on day one

```rust
gossipsub::ConfigBuilder::default()
    .max_transmit_size(4 * 1024 * 1024)      // default 65_536 silently drops blocks
    .message_id_fn(|m| MessageId::from(tagged_hash(TAG_P2P_MSGID, &m.data).as_bytes().to_vec()))
                                             // default is base58(peer)||seqno -> duplicate storms
    .mesh_n_low(4).mesh_n(6).mesh_n_high(12) // default mesh_n_low = 5, spec says 4
    .duplicate_cache_time(Duration::from_secs(120))
    .heartbeat_interval(Duration::from_secs(1))
    .validation_mode(ValidationMode::Strict)
    .validate_messages()                     // explicit report_message_validation_result
    .build()
```
Yamux receive window is raised from the 256 KiB default. Every invalid message is reported with
`MessageAcceptance::Reject` so it feeds gossipsub's **P₄ invalid-message score** — the cheapest DoS
defence available.

### 10.2 Wire protocol

Topics: `ferrum/{chain_id}/blocks/v1`, `ferrum/{chain_id}/txs/v1`.
Sync is a libp2p `request-response` protocol `/ferrum/sync/1.0.0` with borsh-encoded frames:

```rust
pub enum SyncRequest  { GetHeaders { locator: Vec<BlockHash>, stop: Option<BlockHash>, max: u32 },
                        GetBlocks  { hashes: Vec<BlockHash> },
                        GetTip }
pub enum SyncResponse { Headers(Vec<BlockHeader>), Blocks(Vec<Block>), Tip { hash: BlockHash, height: u64, work: [u8;32] }, NotFound }
pub enum GossipMessage { NewBlock(Box<Block>), NewTransaction(Transaction), NewTip { hash: BlockHash, height: u64 } }
```

`max` is capped at 2000 headers and 64 blocks per response, server-side, regardless of the request.

### 10.3 Backpressure

**Zero `unbounded_channel` in the whole workspace** — CI greps for it. Every queue has an explicit
capacity constant in `p2p::limits`, and a full queue load-sheds with a `tracing::warn!` counter
rather than growing.

---

## 11. `ferrum-rpc`

JSON-RPC 2.0 over HTTP and WebSocket (`jsonrpsee` 0.24), plus a small REST surface for the explorer.

```
getblockchaininfo   -> { chain, height, best_hash, total_work, difficulty, engine, finalized_height, mempool_size, utxo_count }
getblockhash        (height)              -> hash
getblock            (hash, verbosity)     -> block
getblockheader      (hash)                -> header
getrawtransaction   (txid)                -> hex | decoded
sendrawtransaction  (hex)                 -> txid
gettxout            (txid, vout)          -> coin | null
getblocktemplate    (payout_address)      -> template
submitblock         (hex)                 -> accepted | reason
getmempoolinfo / getrawmempool
getbalance          (address)             -> { confirmed, immature, utxo_count }     [index required]
listunspent         (address)             -> [ { outpoint, value, height, script } ] [index required]
getstateroot        (height?)             -> hash
getpeerinfo / getnetworkinfo
estimatefee         (blocks)              -> grains per kB
```

REST, EIP-3091 route shape, served by `axum` on the explorer port:
`GET /api/block/:height_or_hash`, `GET /api/tx/:txid`, `GET /api/address/:address`,
`GET /api/stats`, `GET /api/search?q=`, `POST /api/faucet`, and `/` serving the static explorer.

Every RPC error carries a stable numeric code; the table lives in `rpc::error`.

---

## 12. `ferrum-wallet`

```rust
pub struct Wallet { /* encrypted keystore + address book + UTXO cache */ }
impl Wallet {
    pub fn create(path:&Path, network: Network, passphrase:&str, words: usize, rng:&mut impl CryptoRngCore) -> Result<(Self, Mnemonic), WalletError>;
    pub fn restore(path:&Path, network: Network, mnemonic:&Mnemonic, passphrase:&str) -> Result<Self, WalletError>;
    pub fn open(path:&Path, passphrase:&str) -> Result<Self, WalletError>;
    pub fn new_address(&mut self) -> Result<Address, WalletError>;      // m/44'/7767'/0'/0/i
    pub fn addresses(&self) -> Vec<Address>;
    pub fn sync(&mut self, utxos: Vec<(OutPoint, Coin)>, tip: u64);
    pub fn balance(&self, tip_height: u64, maturity: u64) -> Balance;
    pub fn build_transaction(&self, req: &SendRequest, tip_height: u64) -> Result<Transaction, WalletError>;
    pub fn sign_transaction(&self, tx: &mut Transaction, prevouts: &[Coin], chain_id: ChainId) -> Result<(), WalletError>;
}
pub struct SendRequest { pub outputs: Vec<(Address, Amount)>, pub fee_rate: u64, pub change_to: Option<Address> }
pub struct Balance { pub confirmed: Amount, pub immature: Amount, pub pending: Amount }
```

Keystore file: `{ version, network, kdf: {argon2id-or-pbkdf2 params, salt}, nonce, ciphertext }`.
The mnemonic is encrypted at rest; the plaintext seed never touches disk. `SecretKey` and `Mnemonic`
zeroize on drop. Coin selection: **branch-and-bound for an exact match, falling back to
largest-first with a change output**, and it never creates a dust output (below `3 * min_relay_fee`).

---

## 13. `ferrum-node` and `ferrum-cli`

```
chaind --config <file> [--network devnet] [--datadir DIR] [--mine] [--mine-address ADDR]
       [--rpc-listen 127.0.0.1:8645] [--p2p-listen /ip4/0.0.0.0/tcp/8646] [--peer <multiaddr>]...
       [--consensus pow|bft] [--validator-key FILE] [--explorer-listen 0.0.0.0:8647]
       [--metrics-listen 127.0.0.1:9100] [--index] [--log-format text|json]

chain-cli  wallet   new | restore | address | balance | send | list-unspent | dump-seed
           tx       decode | send | get
           block    get | hash | tip
           script   eval | disassemble | build-p2pkh | build-multisig | build-htlc
           chain    info | peers | stateroot | reindex
           genesis  mine   (grind a genesis block for a new network)
           faucet   request
```

Config file is TOML, and every field has a CLI override. Precedence:
**CLI flag > env var (`FERRUM_*`) > config file > network default.**

Node structure: a single `tokio` runtime; `p2p`, `rpc`, `miner`, `explorer` and `metrics` each own a
task; all communicate over bounded channels; a `CancellationToken` gives a clean shutdown on
SIGINT/SIGTERM, and the store is flushed before exit.

---

## 14. Testing contract

| Asset | Where | Gate |
|---|---|---|
| Determinism replay harness | `testing/sim/src/replay.rs` | golden state-root sequence, run in debug **and** release |
| Reference executor (naive, `BTreeMap`, written from this document) | `testing/sim/src/reference.rs` | differential vs `chain::apply_block` on every simulated block |
| Adversarial scenarios | `testing/sim/src/scenarios/` | each red-then-green |
| Decoder fuzz target | `testing/fuzz/fuzz_targets/decode.rs` | no panic |
| Script fuzz target | `testing/fuzz/fuzz_targets/script.rs` | no panic |
| Multi-node e2e | `testing/e2e/tests/` | 4 nodes converge; partition → heal → reorg resolves |
| ASERT cross-check | `testing/reference/asert.py` | 200k pairs match Rust exactly |
| BIP-340 vectors | `crates/crypto/tests/bip340.rs` | all 19 official vectors |
| CVE-2012-2459 | `crates/crypto/tests/merkle.rs` | duplicated-leaf tree root differs |

Mandatory adversarial scenarios, each with a test that fails before the fix and passes after:
timestamp manipulation across a retarget; a 100-block invalid side chain; double-spend within one
block; output-sum overflow; cross-chain signature replay (testnet signature on mainnet); a block
engineered to be expensive to validate; a reorg deeper than the mempool's memory; a coinbase that
overpays by one grain; a duplicate-txid block (BIP-30); non-minimal script number encodings.

---

## 15. Milestone definition of done

| # | Done when this command works |
|---|---|
| M0 | `cargo test -p ferrum-crypto` — tags distinct, BIP-340 vectors, Merkle CVE test, BIP-32/39 vectors |
| M1 | `cargo test -p ferrum-types` — 88-byte header, bidirectional round-trip proptest, 1000 encodings → 1 hash |
| M2 | `chain-cli script eval` runs P2PKH, 2-of-3 multisig and a CLTV timelock; limits reject oversized scripts |
| M3 | apply-then-rollback leaves a byte-identical UTXO set; 50 kill-mid-write restarts are all consistent |
| M4 | `chaind --mine` climbs; ASERT holds block time within 2× across a 10× hashrate spike and collapse; a forced 6-block reorg equals a genesis replay |
| M5 | create wallet → mine → send → confirm → balance read from the UTXO set, never by rescan |
| M6 | `devnet/up.sh` starts 4 nodes; partition, mine both sides, heal, watch the reorg resolve |
| M7 | `/block/:h`, `/tx/:hash`, `/address/:addr` over our own index; one static page; faucet; README a stranger can follow |
| M8 | 3 seeds in 3 regions, public RPC + explorer + faucet, published genesis hash, stranger syncs from zero |
| M9 | same binary, `--consensus bft`, 4 validators: kill 1 → continues; kill 2 → halts, and the docs explain why that is correct |
| M10 | the live chain crosses `bft_activation_height` and changes consensus engine without losing history |
