//! Fuzz the decoder.
//!
//! This is where unauthenticated bytes from anonymous peers land, which makes it
//! the single highest-value fuzz target in the project. Two properties are
//! checked, and the second is the one that matters:
//!
//! 1. **No panic, no unbounded allocation.** A `Vec<T>` length prefix claiming
//!    four billion elements must not become a four-billion-element allocation.
//!
//! 2. **Round-tripping is bijective.** If a byte string decodes, re-encoding the
//!    result must reproduce that byte string *exactly*. This is the direction
//!    that catches non-canonical encodings, and it is the property the
//!    transaction id actually rests on: two byte strings decoding to one value
//!    means one transaction has two identifiers, which is txid malleability.
//!    Bitcoin's `CompactSize` admits several encodings of the same number, and
//!    closing that took years and a soft fork.

#![no_main]

use ferrum_types::{Block, BlockHeader, Coin, OutPoint, Transaction};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The envelope decoder: type byte + borsh transaction. Reserved and unknown
    // type bytes must be rejected rather than silently accepted.
    if let Ok(tx) = Transaction::decode_envelope(data) {
        let reencoded = tx.encode_envelope();
        assert_eq!(
            reencoded.as_slice(),
            data,
            "decode/encode is not bijective: two byte strings decode to one transaction, \
             which means one transaction has two txids"
        );

        // Anything that decoded must survive the accessors without panicking.
        let _ = tx.is_coinbase();
        let _ = tx.total_output();
        let _ = tx.serialized_size();
    }

    // Raw borsh for the structures that arrive over the wire whole.
    if let Ok(block) = borsh::from_slice::<Block>(data) {
        let reencoded = borsh::to_vec(&block).expect("a decoded block must re-encode");
        assert_eq!(reencoded.as_slice(), data, "Block encoding is not bijective");
        let _ = block.serialized_size();
        let _ = block.coinbase();
    }

    if let Ok(header) = borsh::from_slice::<BlockHeader>(data) {
        let reencoded = borsh::to_vec(&header).expect("a decoded header must re-encode");
        assert_eq!(reencoded.as_slice(), data, "BlockHeader encoding is not bijective");
        // The header is a fixed 88 bytes. If this ever fails, every stored header
        // and every published block hash is invalidated.
        assert_eq!(reencoded.len(), 88, "header must be exactly 88 bytes");
    }

    if let Ok(op) = borsh::from_slice::<OutPoint>(data) {
        let reencoded = borsh::to_vec(&op).expect("a decoded outpoint must re-encode");
        assert_eq!(reencoded.as_slice(), data, "OutPoint encoding is not bijective");
    }

    if let Ok(coin) = borsh::from_slice::<Coin>(data) {
        let reencoded = borsh::to_vec(&coin).expect("a decoded coin must re-encode");
        assert_eq!(reencoded.as_slice(), data, "Coin encoding is not bijective");
    }
});
