The official BIP-39 English wordlist: 2048 words, one per line, LF endings.

SHA-256 of this file: 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
That digest is the published checksum for the canonical list, so a corrupted or
reordered copy is detectable. A test asserts it.

Word order is normative: a mnemonic encodes 11-bit indices into this exact
sequence, so reordering it silently changes every seed derived from every phrase.
Do not sort, dedupe or reformat this file.

Source: the BIP-39 specification, obtained via the bip39 crate on crates.io
(github raw was unreachable from this network). Public domain.
