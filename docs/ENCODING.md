# Ferrum canonical encoding

> Normative. Derived from `CONTRACT.md` §1–2, which wins on any conflict.
>
> This document exists because a consensus split from a non-canonical encoding is the cheapest
> catastrophe available to a new chain, and the only reliable defence is writing the rules down
> before the encoder exists and then testing against the written rules rather than against the code.

Every byte that a Ferrum node hashes, signs, stores or sends over the network is produced by the
rules below. There is exactly one valid encoding of any value, and exactly one value behind any
valid encoding. That bijection is the property the whole system rests on: it is what makes a txid
a stable identifier, what makes a signature unforgeable in context, and what makes two independent
nodes agree on a block hash.

---

## 1. Base codec

Ferrum uses **Borsh 1.x** as its base codec. It is not hand-rolled.

The reason is narrow and worth stating. A hand-written codec is one to two weeks of work and
historically produces exactly the bug it was written to prevent — Bitcoin's `CompactSize` admits
several encodings of the same number, and the resulting txid malleability took years and a soft fork
to close. Borsh documents a bijective object↔bytes mapping as its central guarantee. That guarantee
is the entire requirement.

### 1.1 Primitive rules

| Type | Encoding |
|---|---|
| `u8`, `u16`, `u32`, `u64`, `u128` | fixed-width **little-endian** |
| `i8` … `i128` | fixed-width little-endian, two's complement |
| `bool` | `0x00` false, `0x01` true; any other byte is invalid |
| `[T; N]` | `N` elements back to back, **no length prefix** |
| `Vec<T>` | `u32` LE length, then that many elements |
| `String` | `u32` LE byte length, then UTF-8 bytes |
| `Option<T>` | `0x00`, or `0x01` followed by `T` |
| `struct` | fields in declaration order, no padding, no field tags |
| `enum` | `u8` discriminant in declaration order, then that variant's fields |
| newtype `struct S(T)` | exactly the encoding of `T` |

Little-endian is not a preference; it is Borsh's convention, and mixing endianness within one
codec is how field-offset bugs are born. **There is exactly one exception in the whole system:
database keys are big-endian** — see §6.

### 1.2 Decoding is strict

Three rules, all consensus-critical:

1. **Trailing bytes are rejected.** Always `borsh::from_slice`, never a streaming reader that stops
   when it has enough. A decoder that tolerates a suffix admits two byte strings for one value, and
   since the txid is a hash of the byte string, that is txid malleability.
2. **Out-of-range discriminants are rejected.** An `enum` byte outside the declared range is an
   error, never a silent default.
3. **Length prefixes are bounded before allocation.** A `Vec<T>` header claiming four billion
   elements must not cause a four-billion-element allocation. Decode inside a size limit derived
   from the input length.

Rule 3 is the one that matters on the network boundary: those bytes arrive from anonymous peers, and
the decoder is the single most valuable fuzz target in the project.

---

## 2. Transactions

### 2.1 The envelope

```
tx_envelope := type_byte : u8 || borsh(Transaction)
```

| Range | Meaning |
|---|---|
| `0x00` | `Standard` — the only transaction type in v1 |
| `0x01`–`0x7f` | reserved for future transaction types; **rejected** in v1 |
| `0x80`–`0xfe` | reserved; **rejected** in v1 |
| `0xff` | permanently reserved as an extension escape; **always rejected** |

One byte, spent on day one, is what let Ethereum add four transaction types years after launch
(EIP-2718) without breaking anything. It costs a byte per transaction and buys the ability to add a
type without a flag day.

### 2.2 Structure

```rust
Transaction {
    version:   u32,
    inputs:    Vec<TxIn>,
    outputs:   Vec<TxOut>,
    lock_time: u32,
}
TxIn  { prev_out: OutPoint, script_sig: Script, sequence: u32 }
TxOut { value: Amount, script_pubkey: Script }
OutPoint { txid: Txid, vout: u32 }        // 32 + 4 = 36 bytes, fixed
Script   -> Vec<u8>                        // u32 LE length prefix
Amount   -> u64                            // grains, little-endian
```

`lock_time < 500_000_000` is a **block height**; otherwise it is a **Unix timestamp in seconds**.
That threshold is `LOCKTIME_THRESHOLD`, and CLTV compares like-for-like: a height locktime may only
be satisfied by a height, and a timestamp locktime only by a timestamp.

### 2.3 Transaction id

```
txid = tagged_hash("ferrum.v1.txid", tx_envelope)
```

The type byte is **inside** the preimage. There is no separate "witness" serialisation and no
stripped form — Ferrum has no segregated witness, so there is exactly one serialisation of a
transaction and exactly one identifier for it.

Signature malleability, the historical reason for a second identifier, does not exist here: Ferrum
signs with BIP-340 Schnorr, which has no DER encoding to reshape and no low-`s` rule to violate. A
64-byte signature has one valid form.

---

## 3. Block headers — exactly 88 bytes

| Offset | Size | Field | Type |
|---:|---:|---|---|
| 0 | 4 | `version` | `u32` LE |
| 4 | 32 | `prev_hash` | `[u8; 32]` |
| 36 | 32 | `merkle_root` | `[u8; 32]` |
| 68 | 8 | `timestamp_ms` | `u64` LE, Unix milliseconds |
| 76 | 4 | `bits` | `u32` LE, compact target |
| 80 | 8 | `nonce` | `u64` LE |
| | **88** | | |

```
block_hash = tagged_hash("ferrum.v1.header", header_bytes)
```

Two deliberate departures from Bitcoin:

- **`timestamp_ms` is a `u64` of milliseconds.** Bitcoin's `u32` seconds field overflows in 2106.
  Four extra bytes per header removes a problem that its successors have to fork around. Note that
  median-time-past and locktime comparisons are still performed in *seconds* — the units differ on
  purpose, because CLTV semantics are defined in seconds and reproducing them exactly is worth more
  than unit consistency.
- **`nonce` is a `u64`.** A 32-bit nonce exhausts in about four billion hashes, which is why Bitcoin
  miners roll an "extranonce" inside the coinbase and rebuild the Merkle root to keep searching.
  Eight bytes makes that machinery unnecessary.

A test asserts `borsh::to_vec(&header).len() == 88` and checks each field offset against a
hand-built byte array. If that test ever fails, every stored header and every published block hash
is invalidated.

---

## 4. Blocks

```rust
Block {
    header: BlockHeader,
    txs:    Vec<Transaction>,      // txs[0] is the coinbase
    seal:   BlockSeal,
}
BlockSeal { engine: u8, data: Vec<u8> }
```

| `engine` | Meaning | `data` |
|---|---|---|
| `0` | proof of work | empty — the proof *is* the header nonce |
| `1` | BFT | `borsh(BftCommit)` |

**The seal is outside the header and outside `merkle_root`, and that is not an oversight.** A BFT
commit certificate is assembled *after* the header exists, from signatures over that header's hash;
it cannot commit to itself. Keeping it out also means the block hash does not depend on which
`2f+1` subset of signatures a particular node happened to collect first, so two honest nodes that
saw different quorums still agree on the block's identity.

The direct consequence is that the PoW→BFT hard fork changes no serialised structure whatsoever. It
is a dispatcher selecting a different engine above an activation height. See `DECISIONS.md` D2.

### 4.1 Merkle root

Leaves are the 32-byte txids of `txs`, in block order.

```
leaf(d)        = tagged_hash("ferrum.v1.merkle.leaf", d)
node(l, r)     = tagged_hash("ferrum.v1.merkle.node", l || r)
merkle_root([]) = 0x00 * 32
```

An odd node at any level is **promoted** to the next level unchanged. It is never duplicated.

This is the fix for **CVE-2012-2459**. Duplicating the final node makes the tree of
`[a, b, c]` and `[a, b, c, c]` produce the same root, so an attacker can take a valid block, append
a duplicate transaction, and produce a block with a matching header that fails transaction-level
validation — permanently marking the *real* block invalid in any node that caches the failure.
Bitcoin Core's `consensus/merkle.cpp` carries a comment addressed specifically to people building
new systems, warning about this.

Domain-separating leaves from internal nodes (the RFC 6962 shape) closes the second half of the
problem: without it, a 32-byte "transaction" could be presented as an internal node, forging a proof.

---

## 5. Signature hashing

The preimage is fixed and complete. Every field is present at a fixed position; nothing is optional
and nothing is variable-length except `script_code`, which carries its own length.

```
sighash_preimage :=
     chain_id        : u32 LE
  || tx_version      : u32 LE
  || hash_prevouts   : 32
  || hash_sequences  : 32
  || input_index     : u32 LE
  || outpoint        : 36
  || script_code_len : u32 LE
  || script_code     : bytes
  || input_value     : u64 LE
  || input_sequence  : u32 LE
  || hash_outputs    : 32
  || lock_time       : u32 LE
  || sighash_type    : u8

sighash := tagged_hash("ferrum.v1.sighash", sighash_preimage)
```

Sub-hashes, each `tagged_hash("ferrum.v1.sighash", ·)` over the concatenation:

| Field | `ALL` | `NONE` | `SINGLE` | `+ANYONECANPAY` |
|---|---|---|---|---|
| `hash_prevouts` | all input outpoints | same | same | 32 zero bytes |
| `hash_sequences` | all input sequences | 32 zero bytes | 32 zero bytes | 32 zero bytes |
| `hash_outputs` | all outputs | 32 zero bytes | just `outputs[input_index]` | unchanged by the flag |

`SigHashType`: `ALL = 0x01`, `NONE = 0x02`, `SINGLE = 0x03`, `ANYONECANPAY = 0x80` as a flag on any
of them. Any other byte is invalid.

`SINGLE` with `input_index >= outputs.len()` is an **error**. Bitcoin returns the constant
`uint256(1)` in that case, which is signable and has cost real money; there is no reason to
reproduce it.

Three fields carry most of the weight:

- **`chain_id`.** A signature made on testnet cannot be replayed on mainnet. Ethereum retrofitted
  this as EIP-155 after the DAO fork split the chain and users lost funds to cross-chain replay. It
  costs four bytes here and is untestable-after-the-fact if omitted.
- **`input_value`.** The amount being spent is committed to. Without it — Bitcoin's legacy
  sighash — an offline signer cannot know how much it is authorising, which is what BIP-143 was
  written to fix.
- **`hash_prevouts` / `hash_sequences` / `hash_outputs` as precomputed digests.** Legacy Bitcoin
  sighash rehashes the whole transaction once per input, making validation O(n²) in the number of
  inputs; a single 1 MB transaction could be made to take minutes to verify. Precomputing three
  digests per transaction makes it O(n).

A signature inside a `script_sig` is exactly **65 bytes**: 64-byte Schnorr signature followed by the
one-byte sighash type. Any other length fails.

---

## 6. Database keys — the one big-endian exception

Every ordered key-value store, `redb` included, sorts keys **bytewise**. For that ordering to match
numeric ordering, multi-byte numbers in keys must be big-endian.

| Table | Key |
|---|---|
| `blocks` | `block_hash[32]` |
| `headers` | `block_hash[32]` |
| `height` | `be_u64(height)` |
| `utxo` | `borsh(OutPoint)` — 36 bytes |
| `undo` | `block_hash[32]` |
| `meta` | ASCII key string |
| `tx_index` | `txid[32]` |
| `addr_index` | `addr_key ‖ be_u64(height) ‖ be_u32(tx_index)` |

With little-endian height keys, `1` encodes as `01 00 00 00 00 00 00 00` and `256` as
`00 01 00 00 00 00 00 00`, so a bytewise scan puts 256 *before* 1. Every range scan and every
"iterate the chain in order" silently breaks at block 256 — late enough that unit tests on a
five-block fixture pass, early enough to be discovered in production. A test inserts heights
1, 255, 256, 65535, 65536 and 2³² and asserts an ordered scan returns them in numeric order.

`addr_index` is composite precisely so that a single ordered range scan returns one address's
history in height order, which is the only query the explorer needs.

---

## 7. Text encodings

### 7.1 Hashes

Lowercase hex of the bytes **in natural order**. Ferrum does not reverse.

Bitcoin displays hashes byte-reversed because its internal `uint256` is little-endian and that
detail leaked into RPC output; every tool since has had to know which of the two orders it is
holding. `FromStr` accepts 64 hex characters, case-insensitive, with an optional `0x` prefix.

### 7.2 Addresses — bech32m

```
address := bech32m( hrp, [version_u5] ++ convertbits(payload, 8, 5, pad=true) )
```

| Network | HRP | Version | Payload |
|---|---|---|---|
| Mainnet | `fer` | 0 | `hash160(x_only_pubkey)`, 20 bytes — P2PKH |
| Testnet | `tfer` | 1 | `tagged_hash("ferrum.v1.script", redeem_script)`, 32 bytes — P2SH |
| Devnet | `rfer` | | |

**bech32m, not bech32.** The original bech32 checksum has a flaw in which a final character
insertion or deletion can go undetected when the data part ends in specific values; BIP-350 changed
the constant from `1` to `0x2bc830a3` to fix it. Since Ferrum has no legacy addresses to remain
compatible with, there is no reason to inherit the flaw.

Decoding rejects: a wrong HRP for the network, a bad checksum, a bech32 (non-`m`) checksum, an
unknown version byte, and a payload length that does not match the version.

The HRP separation means a mainnet address is a decode *error* on testnet, not a silently valid
address — the same class of protection that `chain_id` gives signatures.

---

## 8. Amounts

`Amount` wraps a `u64` count of **grains**. `1 FRM = 100_000_000 grain`. Maximum money is
`21_000_000 FRM = 2_100_000_000_000_000 grains`, comfortably inside `u64`.

Text form is a fixed-point decimal with at most 8 fractional digits, parsed with integer arithmetic
only. `"1"`, `"1.5"`, `"0.00000001"` are valid; `"1.234567891"` (9 dp), `".5"`, `"1.2.3"`, `"-1"`
and `"1e8"` are not. There is no float anywhere on this path — a float parse of `"0.1"` is not
`0.1`, and money must not round.

`Amount` deliberately implements **no `Add` or `Sub`**. Every monetary operation goes through
`checked_add`, `checked_sub` or `checked_mul_u64`, whose `None` becomes a typed error. An inflation
bug therefore cannot be written by accident; it has to be written on purpose, via `.to_grains()`,
which is greppable in review. See `DECISIONS.md` D7.

---

## 9. Domain separation

Every hash in Ferrum is computed as BLAKE3 in derive-key mode:

```rust
blake3::Hasher::new_derive_key("ferrum.v1.<purpose>").update(data).finalize()
```

The context string is a compile-time constant drawn from the frozen list in `CONTRACT.md` §1.
Adding a tag is permitted; changing or removing one is a hard fork.

Without this, a 32-byte digest is just a 32-byte digest, and a structure signed in one context can
be presented in another — the canonical failure being a signature over a consensus vote replayed as
a transaction authorisation. A test asserts all tags are pairwise distinct and that
`tagged_hash(a, x) != tagged_hash(b, x)` for every pair of tags over several inputs.

The hasher for each tag is constructed once behind a `LazyLock` and cloned per call. Re-deriving the
context key on every hash roughly halves mining throughput for no benefit.

---

## 10. What is tested, and why those tests

| Property | Test |
|---|---|
| Header is exactly 88 bytes, at the stated offsets | `crates/types/tests/encoding.rs` |
| `decode(encode(v)) == v` | proptest, every consensus type |
| `encode(decode(b)) == b` for every decodable `b` | proptest — the direction that catches non-canonical forms |
| One value has exactly one encoding | encode the same transaction 1000 times, assert one distinct hash |
| Trailing bytes rejected | `decode_envelope(valid ++ [0])` is an error |
| Reserved type bytes rejected | every byte in `0x01..=0xff` fails |
| Big-endian key ordering | insert 1, 255, 256, 65535, 65536, 2³²; assert scan order |
| Merkle promotes rather than duplicates | root of `[a,b,c]` ≠ root of `[a,b,c,c]`, for n in 1..=16 |
| Domain tags are distinct | all pairs, several inputs |
| Cross-chain replay fails | a signature under `ChainId(2)` fails under `ChainId(1)` |

The second row is the one that is usually missing. `decode(encode(v)) == v` alone will happily pass
on a codec that accepts three different byte strings for the same value; only the reverse direction
catches it, and only the reverse direction is the property that actually protects the txid.
