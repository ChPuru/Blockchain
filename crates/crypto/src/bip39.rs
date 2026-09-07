//! BIP-39 mnemonics over the official English wordlist.
//!
//! A [`Mnemonic`] is 12, 15, 18, 21 or 24 words encoding 128 to 256 bits of
//! entropy plus a 4- to 8-bit SHA-256 checksum. [`Mnemonic::to_seed`] runs
//! PBKDF2-HMAC-SHA512 for 2048 rounds with the salt `"mnemonic" || passphrase`
//! and produces the 64-byte seed that [`crate::ExtendedKey::master_from_seed`]
//! consumes.
//!
//! # The wordlist is normative
//!
//! `src/wordlist/english.txt` is the published BIP-39 English list: 2048
//! words, one per line, in the specification's order, embedded with
//! `include_str!`. **The order is part of the format** — a mnemonic encodes
//! 11-bit indices into that exact sequence, so sorting, deduplicating or
//! regenerating the file silently changes every seed derived from every
//! phrase. A test pins the file's SHA-256 to the published digest.
//!
//! # Normalisation
//!
//! Input is NFKD-normalised before anything else, as BIP-39 requires, and the
//! canonical phrase this type stores is the NFKD form with words joined by a
//! single ASCII space. The passphrase handed to [`Mnemonic::to_seed`] is
//! NFKD-normalised too. Without that, a phrase typed on macOS (NFD) and the
//! same phrase typed on Windows (NFC) would derive different wallets.
//!
//! # Zeroization
//!
//! The phrase is held in a `Zeroizing<String>` and comparison is
//! constant-time. `Debug` never prints it.
//!
//! ```
//! use ferrum_crypto::Mnemonic;
//!
//! let m = Mnemonic::from_entropy(&[0u8; 16])?;
//! assert_eq!(m.phrase().split(' ').count(), 12);
//! assert!(m.phrase().starts_with("abandon abandon"));
//! # Ok::<(), ferrum_crypto::CryptoError>(())
//! ```

use std::fmt;
use std::sync::LazyLock;

use hmac::Hmac;
use sha2::Sha512;
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;
use crate::hashing::sha256;

/// The number of words in the BIP-39 wordlist. Also `2^11`, which is why each
/// word carries exactly 11 bits.
pub const WORDLIST_LEN: usize = 2048;

/// Bits of entropy contributed by one word.
const BITS_PER_WORD: usize = 11;

/// Bytes to reserve per word when building a phrase: the longest word in the
/// English wordlist is 8 bytes, plus the single space that follows it.
///
/// Reserving is not an optimisation here — see [`Mnemonic::from_entropy`].
const MAX_WORD_BYTES: usize = 9;

/// PBKDF2 iteration count fixed by BIP-39.
pub const PBKDF2_ROUNDS: u32 = 2048;

/// Length of the seed BIP-39 produces, in bytes.
pub const SEED_LEN: usize = 64;

/// The word counts a Ferrum mnemonic may have.
pub const VALID_WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

/// The embedded, normative BIP-39 English wordlist.
const ENGLISH_TXT: &str = include_str!("wordlist/english.txt");

/// The wordlist split into 2048 entries, in normative order.
static ENGLISH: LazyLock<[&'static str; WORDLIST_LEN]> = LazyLock::new(|| {
    let mut words = [""; WORDLIST_LEN];
    let mut lines = ENGLISH_TXT.lines();
    for slot in words.iter_mut() {
        *slot = lines.next().expect("the embedded BIP-39 wordlist has exactly 2048 lines");
    }
    assert!(lines.next().is_none(), "the embedded BIP-39 wordlist has exactly 2048 lines");
    words
});

/// The official BIP-39 English wordlist, in normative order.
///
/// Exposed so a wallet UI can offer word completion without re-embedding the
/// list, and so tests can assert its shape.
pub fn english_wordlist() -> &'static [&'static str; WORDLIST_LEN] {
    &ENGLISH
}

/// The index of `word` in the English wordlist.
///
/// A binary search is valid because the list is strictly ascending, which a
/// test asserts.
fn word_index(word: &str) -> Option<usize> {
    ENGLISH.binary_search(&word).ok()
}

/// Entropy bytes for a given word count, or `None` if the count is invalid.
fn entropy_len_for(words: usize) -> Option<usize> {
    // 12 -> 16, 15 -> 20, 18 -> 24, 21 -> 28, 24 -> 32.
    VALID_WORD_COUNTS.contains(&words).then(|| words / 3 * 4)
}

/// Checksum bits for a given word count. Always `entropy_bits / 32`.
fn checksum_bits_for(words: usize) -> usize {
    words / 3
}

/// A BIP-39 mnemonic phrase.
///
/// Stores the NFKD-normalised phrase with words joined by a single space, and
/// zeroizes it on drop.
#[derive(Clone)]
pub struct Mnemonic(Zeroizing<String>);

impl Mnemonic {
    /// Generate a fresh mnemonic with `words` words from a cryptographic RNG.
    ///
    /// `words` must be 12, 15, 18, 21 or 24.
    pub fn generate(
        words: usize,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<Self, CryptoError> {
        let entropy_len = entropy_len_for(words).ok_or(CryptoError::InvalidWordCount(words))?;
        let mut entropy = Zeroizing::new(vec![0u8; entropy_len]);
        rng.fill_bytes(&mut entropy);
        Mnemonic::from_entropy(&entropy)
    }

    /// Build a mnemonic from raw entropy of 16, 20, 24, 28 or 32 bytes.
    ///
    /// This is the constructor the BIP-39 test vectors drive, and the one
    /// [`Mnemonic::generate`] uses once it has drawn its bytes.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, CryptoError> {
        let entropy_len = entropy.len();
        if !matches!(entropy_len, 16 | 20 | 24 | 28 | 32) {
            return Err(CryptoError::InvalidEntropyLength(entropy_len));
        }
        let checksum_bits = entropy_len / 4;
        let word_count = (entropy_len * 8 + checksum_bits) / BITS_PER_WORD;

        // entropy || first checksum byte; only the top `checksum_bits` of the
        // appended byte are ever read.
        let mut buf = Zeroizing::new(Vec::with_capacity(entropy_len + 1));
        buf.extend_from_slice(entropy);
        buf.push(sha256(entropy)[0]);

        // Sized once, up front, and never grown. A `String` that reallocates
        // copies the phrase into a new buffer and frees the old one *without
        // scrubbing it* — `Zeroizing` can only clear the buffer that is live
        // when it drops, so a growing phrase leaves a plaintext prefix of
        // itself in freed heap for a core dump or a heap-reuse read to find.
        // The longest word in the English wordlist is 8 bytes, plus one
        // separator each, which a test pins.
        let mut phrase = Zeroizing::new(String::with_capacity(word_count * MAX_WORD_BYTES));
        for i in 0..word_count {
            let index = read_bits(&buf, i * BITS_PER_WORD, BITS_PER_WORD);
            if i > 0 {
                phrase.push(' ');
            }
            phrase.push_str(
                ENGLISH.get(index).copied().expect("an 11-bit index is always below 2048"),
            );
        }
        Ok(Mnemonic(phrase))
    }

    /// Parse and validate a phrase.
    ///
    /// The input is NFKD-normalised, split on any Unicode whitespace, checked
    /// against the English wordlist, and its checksum verified.
    pub fn from_phrase(s: &str) -> Result<Self, CryptoError> {
        let normalized = Zeroizing::new(s.nfkd().collect::<String>());
        let words: Vec<&str> = normalized.split_whitespace().collect();
        let word_count = words.len();
        let entropy_len =
            entropy_len_for(word_count).ok_or(CryptoError::InvalidWordCount(word_count))?;
        let checksum_bits = checksum_bits_for(word_count);

        let mut indices = Vec::with_capacity(word_count);
        for word in &words {
            let index =
                word_index(word).ok_or_else(|| CryptoError::UnknownWord((*word).to_owned()))?;
            indices.push(index);
        }

        // Repack the 11-bit groups into `entropy || checksum byte`.
        let mut buf = Zeroizing::new(vec![0u8; entropy_len + 1]);
        for (i, index) in indices.iter().enumerate() {
            write_bits(&mut buf, i * BITS_PER_WORD, BITS_PER_WORD, *index);
        }

        let mask: u8 = if checksum_bits >= 8 { 0xff } else { 0xffu8 << (8 - checksum_bits) };
        let expected = sha256(&buf[..entropy_len])[0];
        let actual = buf[entropy_len];
        if (expected & mask) != (actual & mask) {
            return Err(CryptoError::InvalidMnemonicChecksum);
        }

        Ok(Mnemonic(Zeroizing::new(words.join(" "))))
    }

    /// The canonical NFKD phrase, words joined by a single space.
    pub fn phrase(&self) -> &str {
        &self.0
    }

    /// How many words the phrase has.
    pub fn word_count(&self) -> usize {
        self.0.split(' ').count()
    }

    /// Recover the entropy this phrase encodes.
    ///
    /// Zeroizing, because the entropy is exactly as secret as the phrase.
    pub fn to_entropy(&self) -> Zeroizing<Vec<u8>> {
        let word_count = self.word_count();
        // Both invariants below hold for every `Mnemonic` that exists: the two
        // constructors are the only way in and each validates them.
        let entropy_len =
            entropy_len_for(word_count).expect("a Mnemonic always has a valid word count");
        let mut buf = Zeroizing::new(vec![0u8; entropy_len + 1]);
        for (i, word) in self.0.split(' ').enumerate() {
            let index = word_index(word).expect("a Mnemonic only holds wordlist words");
            write_bits(&mut buf, i * BITS_PER_WORD, BITS_PER_WORD, index);
        }
        Zeroizing::new(buf[..entropy_len].to_vec())
    }

    /// The 64-byte BIP-39 seed: PBKDF2-HMAC-SHA512, 2048 rounds, salt
    /// `"mnemonic" || NFKD(passphrase)`.
    ///
    /// The passphrase is the "25th word": a wrong one yields a different, but
    /// perfectly valid, wallet. There is no way to detect the mistake, which
    /// is the whole point of the plausible-deniability design.
    pub fn to_seed(&self, passphrase: &str) -> [u8; SEED_LEN] {
        let normalized_passphrase = Zeroizing::new(passphrase.nfkd().collect::<String>());
        let mut salt = Zeroizing::new(Vec::with_capacity(8 + normalized_passphrase.len()));
        salt.extend_from_slice(b"mnemonic");
        salt.extend_from_slice(normalized_passphrase.as_bytes());

        let mut seed = [0u8; SEED_LEN];
        // The `hmac` feature of `pbkdf2` is off in this workspace, so drive the
        // generic PRF form directly. HMAC accepts a key of any length, so the
        // only error this can return is unreachable.
        pbkdf2::pbkdf2::<Hmac<Sha512>>(self.0.as_bytes(), &salt, PBKDF2_ROUNDS, &mut seed)
            .expect("HMAC-SHA512 accepts a key of any length");
        seed
    }
}

impl PartialEq for Mnemonic {
    /// Constant-time in the phrase bytes; length is not secret.
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && bool::from(self.0.as_bytes().ct_eq(other.0.as_bytes()))
    }
}

impl Eq for Mnemonic {}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A phrase in a log line is a stolen wallet.
        write!(f, "Mnemonic(<redacted, {} words>)", self.word_count())
    }
}

impl std::str::FromStr for Mnemonic {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Mnemonic::from_phrase(s)
    }
}

/// Read `count` big-endian bits starting at bit `offset`.
fn read_bits(buf: &[u8], offset: usize, count: usize) -> usize {
    let mut value = 0usize;
    for i in 0..count {
        let pos = offset + i;
        let byte = buf.get(pos / 8).copied().unwrap_or(0);
        let bit = (byte >> (7 - (pos % 8))) & 1;
        value = (value << 1) | usize::from(bit);
    }
    value
}

/// Write the low `count` bits of `value` big-endian at bit `offset`.
fn write_bits(buf: &mut [u8], offset: usize, count: usize, value: usize) {
    for i in 0..count {
        if (value >> (count - 1 - i)) & 1 == 1 {
            let pos = offset + i;
            if let Some(byte) = buf.get_mut(pos / 8) {
                *byte |= 1u8 << (7 - (pos % 8));
            }
        }
    }
}

/// Zeroize helper so a caller can scrub a seed once it has been consumed.
///
/// `[u8; 64]` has no `Drop`, so a seed left on the stack survives until the
/// frame is reused. Call this the moment the master key exists.
pub fn zeroize_seed(seed: &mut [u8; SEED_LEN]) {
    seed.zeroize();
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn wordlist_has_exactly_2048_entries() {
        assert_eq!(english_wordlist().len(), WORDLIST_LEN);
        assert_eq!(ENGLISH_TXT.lines().count(), WORDLIST_LEN);
    }

    #[test]
    fn wordlist_is_strictly_ascending_and_unique() {
        let words = english_wordlist();
        for pair in words.windows(2) {
            assert!(pair[0] < pair[1], "{:?} is not before {:?}", pair[0], pair[1]);
        }
    }

    #[test]
    fn wordlist_endpoints_are_the_published_ones() {
        let words = english_wordlist();
        assert_eq!(words[0], "abandon");
        assert_eq!(words[WORDLIST_LEN - 1], "zoo");
    }

    #[test]
    fn wordlist_file_matches_its_published_digest() {
        assert_eq!(
            hex::encode(sha256(ENGLISH_TXT.as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
            "the embedded wordlist has been altered; every derived seed changes"
        );
    }

    #[test]
    fn every_word_is_findable_at_its_own_index() {
        for (i, word) in english_wordlist().iter().enumerate() {
            assert_eq!(word_index(word), Some(i));
        }
        assert_eq!(word_index("frobnicate"), None);
        assert_eq!(word_index(""), None);
    }

    #[test]
    fn bit_helpers_round_trip() {
        let mut buf = [0u8; 4];
        write_bits(&mut buf, 0, 11, 0b101_0101_0101);
        write_bits(&mut buf, 11, 11, 0b010_1010_1010);
        assert_eq!(read_bits(&buf, 0, 11), 0b101_0101_0101);
        assert_eq!(read_bits(&buf, 11, 11), 0b010_1010_1010);
    }

    #[test]
    fn all_valid_word_counts_are_generated_and_parsed() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for words in VALID_WORD_COUNTS {
            let m = Mnemonic::generate(words, &mut rng).unwrap();
            assert_eq!(m.word_count(), words);
            assert_eq!(Mnemonic::from_phrase(m.phrase()).unwrap(), m);
        }
    }

    #[test]
    fn invalid_word_counts_are_rejected() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for bad in [0usize, 1, 11, 13, 23, 25, 48] {
            assert_eq!(Mnemonic::generate(bad, &mut rng), Err(CryptoError::InvalidWordCount(bad)));
        }
        assert_eq!(
            Mnemonic::from_phrase("abandon abandon abandon"),
            Err(CryptoError::InvalidWordCount(3))
        );
    }

    #[test]
    fn invalid_entropy_lengths_are_rejected() {
        for bad in [0usize, 1, 15, 17, 31, 33, 64] {
            assert_eq!(
                Mnemonic::from_entropy(&vec![0u8; bad]),
                Err(CryptoError::InvalidEntropyLength(bad))
            );
        }
    }

    #[test]
    fn a_wrong_word_is_rejected_by_name() {
        let phrase = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon frobnicate";
        assert_eq!(
            Mnemonic::from_phrase(phrase),
            Err(CryptoError::UnknownWord("frobnicate".to_owned()))
        );
    }

    #[test]
    fn a_broken_checksum_is_rejected() {
        // The last word carries the checksum; swapping it for another valid
        // word almost always breaks it.
        let phrase = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon zoo";
        assert_eq!(Mnemonic::from_phrase(phrase), Err(CryptoError::InvalidMnemonicChecksum));
    }

    #[test]
    fn swapping_two_words_breaks_the_checksum() {
        let m = Mnemonic::from_entropy(&[0x11u8; 32]).unwrap();
        let mut words: Vec<&str> = m.phrase().split(' ').collect();
        words.swap(0, 1);
        assert_eq!(
            Mnemonic::from_phrase(&words.join(" ")),
            Err(CryptoError::InvalidMnemonicChecksum)
        );
    }

    #[test]
    fn entropy_round_trips_through_the_phrase() {
        for len in [16usize, 20, 24, 28, 32] {
            let entropy: Vec<u8> =
                (0..len).map(|i| u8::try_from(i * 7 % 251).unwrap_or(0)).collect();
            let m = Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(m.to_entropy().to_vec(), entropy);
            assert_eq!(Mnemonic::from_phrase(m.phrase()).unwrap().to_entropy().to_vec(), entropy);
        }
    }

    #[test]
    fn whitespace_and_case_are_normalised_on_parse() {
        let canonical = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let messy = format!("  {}  ", canonical.phrase().replace(' ', "\t \n"));
        assert_eq!(Mnemonic::from_phrase(&messy).unwrap(), canonical);
        assert_eq!(Mnemonic::from_phrase(&messy).unwrap().phrase(), canonical.phrase());
    }

    #[test]
    fn nfkd_normalisation_is_applied_to_the_phrase() {
        // U+FB01 LATIN SMALL LIGATURE FI decomposes to "fi" under NFKD. Find a
        // real, checksum-valid phrase containing a word with "fi", rewrite that
        // occurrence with the ligature, and require it to parse identically.
        let mut found = None;
        for seed in 0u8..64 {
            let m = Mnemonic::from_entropy(&[seed; 16]).unwrap();
            if m.phrase().contains("fi") {
                found = Some(m);
                break;
            }
        }
        let canonical = found.expect("some 12-word phrase contains a word with 'fi'");
        let with_ligature = canonical.phrase().replacen("fi", "\u{fb01}", 1);
        assert_ne!(with_ligature, canonical.phrase(), "the substitution must change the bytes");
        assert_eq!(
            Mnemonic::from_phrase(&with_ligature).unwrap(),
            canonical,
            "NFKD must fold the ligature back to 'fi'"
        );
    }

    #[test]
    fn nfkd_normalisation_is_applied_to_the_passphrase() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(
            m.to_seed("\u{fb01}"),
            m.to_seed("fi"),
            "the passphrase must be NFKD-normalised before PBKDF2"
        );
    }

    #[test]
    fn a_passphrase_changes_the_seed() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_ne!(m.to_seed(""), m.to_seed("TREZOR"));
        assert_eq!(m.to_seed("x"), m.to_seed("x"));
        assert_eq!(m.to_seed("").len(), SEED_LEN);
    }

    #[test]
    fn debug_never_leaks_the_phrase() {
        let m = Mnemonic::from_entropy(&[0u8; 32]).unwrap();
        let shown = format!("{m:?}");
        assert_eq!(shown, "Mnemonic(<redacted, 24 words>)");
        assert!(!shown.contains("abandon"));
    }

    #[test]
    fn from_str_is_from_phrase() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(m.phrase().parse::<Mnemonic>().unwrap(), m);
    }

    #[test]
    fn the_longest_word_fits_the_reserved_size() {
        let longest = english_wordlist().iter().map(|w| w.len()).max().unwrap_or(0);
        assert!(longest < MAX_WORD_BYTES, "a {longest}-byte word plus a space needs more room");
    }

    #[test]
    fn from_entropy_builds_the_phrase_without_reallocating() {
        // A reallocation leaves an unzeroized prefix of the phrase in freed
        // heap, which is nine of the twelve words of a fresh wallet. The
        // observable proof that none happened is that the buffer still has
        // exactly the capacity that was reserved before the first word: a
        // grown `String` would be at a power of two above it.
        for words in VALID_WORD_COUNTS {
            let entropy = vec![0x5au8; entropy_len_for(words).unwrap()];
            let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(
                mnemonic.0.capacity(),
                words * MAX_WORD_BYTES,
                "the {words}-word phrase buffer was reallocated while being built",
            );
            assert!(mnemonic.0.len() <= mnemonic.0.capacity());
        }
    }

    #[test]
    fn zeroize_seed_clears_it() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let mut seed = m.to_seed("");
        assert_ne!(seed, [0u8; SEED_LEN]);
        zeroize_seed(&mut seed);
        assert_eq!(seed, [0u8; SEED_LEN]);
    }
}
