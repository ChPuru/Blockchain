//! Derivation paths: [`ChildNumber`], [`DerivationPath`] and the BIP-44
//! constants Ferrum pins.
//!
//! Split out of `bip32.rs` purely for file size; everything here is
//! re-exported from [`crate::bip32`] and from the crate root, so
//! `ferrum_crypto::DerivationPath` is the path callers use.

use std::fmt;
use std::str::FromStr;

use crate::error::CryptoError;

/// The self-assigned SLIP-44-style coin type for Ferrum.
pub const COIN_TYPE: u32 = 7767;

/// BIP-44 purpose. Present so a path can be built without a magic number.
pub const BIP44_PURPOSE: u32 = 44;

/// The bit that marks a child index as hardened.
pub const HARDENED_BIT: u32 = 0x8000_0000;

/// One step in a derivation path: an index plus whether it is hardened.
///
/// A hardened child has bit 31 of the raw value set and is derived from the
/// parent *private* key, so it cannot be derived from a public key alone.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChildNumber(u32);

impl ChildNumber {
    /// The first normal child, `0`.
    pub const ZERO: ChildNumber = ChildNumber(0);

    /// Wrap a raw value, hardened bit and all.
    pub const fn from_raw(raw: u32) -> Self {
        ChildNumber(raw)
    }

    /// A normal (non-hardened) child. `index` must be below `2^31`.
    pub fn normal(index: u32) -> Result<Self, CryptoError> {
        if index >= HARDENED_BIT {
            return Err(CryptoError::InvalidChildNumber(index));
        }
        Ok(ChildNumber(index))
    }

    /// A hardened child. `index` must be below `2^31`; the bit is added here.
    pub fn hardened(index: u32) -> Result<Self, CryptoError> {
        if index >= HARDENED_BIT {
            return Err(CryptoError::InvalidChildNumber(index));
        }
        Ok(ChildNumber(index | HARDENED_BIT))
    }

    /// True when bit 31 is set.
    pub const fn is_hardened(self) -> bool {
        self.0 & HARDENED_BIT != 0
    }

    /// The index with the hardened bit stripped, as written in a path.
    pub const fn index(self) -> u32 {
        self.0 & !HARDENED_BIT
    }

    /// The raw value that goes into the HMAC, big-endian.
    pub const fn to_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.index())?;
        if self.is_hardened() {
            f.write_str("'")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChildNumber({self})")
    }
}

impl FromStr for ChildNumber {
    type Err = CryptoError;

    /// Accepts `0`, `0'`, `0h` and `0H`, matching every wallet in the wild.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (digits, hardened) = match s.strip_suffix(['\'', 'h', 'H']) {
            Some(rest) => (rest, true),
            None => (s, false),
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CryptoError::InvalidDerivationPath(s.to_owned()));
        }
        let index: u32 =
            digits.parse().map_err(|_| CryptoError::InvalidDerivationPath(s.to_owned()))?;
        if hardened { ChildNumber::hardened(index) } else { ChildNumber::normal(index) }
    }
}

/// An ordered list of [`ChildNumber`]s, written `m/44'/7767'/0'/0/0`.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DerivationPath(Vec<ChildNumber>);

impl DerivationPath {
    /// The empty path, meaning the master key itself.
    pub fn master() -> Self {
        DerivationPath(Vec::new())
    }

    /// Wrap an explicit list of steps.
    pub fn new(steps: Vec<ChildNumber>) -> Self {
        DerivationPath(steps)
    }

    /// The steps, in order.
    pub fn as_slice(&self) -> &[ChildNumber] {
        &self.0
    }

    /// Iterate the steps.
    pub fn iter(&self) -> std::slice::Iter<'_, ChildNumber> {
        self.0.iter()
    }

    /// Number of steps.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True for the master path `m`.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// This path extended by one step.
    pub fn child(&self, step: ChildNumber) -> Self {
        let mut steps = self.0.clone();
        steps.push(step);
        DerivationPath(steps)
    }

    /// The BIP-44 account path `m/44'/7767'/account'`.
    pub fn ferrum_account(account: u32) -> Result<Self, CryptoError> {
        Ok(DerivationPath(vec![
            ChildNumber::hardened(BIP44_PURPOSE)?,
            ChildNumber::hardened(COIN_TYPE)?,
            ChildNumber::hardened(account)?,
        ]))
    }

    /// The full BIP-44 address path `m/44'/7767'/account'/change/index`.
    ///
    /// `change` is 0 for receive addresses and 1 for change addresses, which is
    /// the convention `ferrum-wallet` follows.
    pub fn ferrum(account: u32, change: u32, index: u32) -> Result<Self, CryptoError> {
        let mut path = DerivationPath::ferrum_account(account)?;
        path.0.push(ChildNumber::normal(change)?);
        path.0.push(ChildNumber::normal(index)?);
        Ok(path)
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for step in &self.0 {
            write!(f, "/{step}")?;
        }
        Ok(())
    }
}

impl FromStr for DerivationPath {
    type Err = CryptoError;

    /// Requires the leading `m` (or `M`). A bare `44'/0'` is rejected: an
    /// ambiguous path is how a wallet ends up deriving into the wrong tree.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let mut parts = trimmed.split('/');
        match parts.next() {
            Some("m") | Some("M") => {}
            _ => return Err(CryptoError::InvalidDerivationPath(s.to_owned())),
        }
        let mut steps = Vec::new();
        for part in parts {
            steps.push(part.parse::<ChildNumber>()?);
        }
        Ok(DerivationPath(steps))
    }
}

impl<'a> IntoIterator for &'a DerivationPath {
    type Item = &'a ChildNumber;
    type IntoIter = std::slice::Iter<'a, ChildNumber>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn child_number_hardening() {
        let n = ChildNumber::normal(5).unwrap();
        assert!(!n.is_hardened());
        assert_eq!(n.index(), 5);
        assert_eq!(n.to_u32(), 5);

        let h = ChildNumber::hardened(5).unwrap();
        assert!(h.is_hardened());
        assert_eq!(h.index(), 5);
        assert_eq!(h.to_u32(), 5 | HARDENED_BIT);
        assert_ne!(n, h);
    }

    #[test]
    fn child_number_rejects_out_of_range_indices() {
        assert_eq!(
            ChildNumber::normal(HARDENED_BIT),
            Err(CryptoError::InvalidChildNumber(HARDENED_BIT))
        );
        assert_eq!(ChildNumber::hardened(u32::MAX), Err(CryptoError::InvalidChildNumber(u32::MAX)));
    }

    #[test]
    fn child_number_display_and_parse() {
        assert_eq!(ChildNumber::normal(7).unwrap().to_string(), "7");
        assert_eq!(ChildNumber::hardened(7).unwrap().to_string(), "7'");
        assert_eq!("7".parse::<ChildNumber>().unwrap(), ChildNumber::normal(7).unwrap());
        for s in ["7'", "7h", "7H"] {
            assert_eq!(s.parse::<ChildNumber>().unwrap(), ChildNumber::hardened(7).unwrap());
        }
        assert_eq!(format!("{:?}", ChildNumber::hardened(7).unwrap()), "ChildNumber(7')");
    }

    #[test]
    fn child_number_rejects_junk() {
        for bad in ["", "'", "x", "-1", "1x", "1''", " 1"] {
            assert!(bad.parse::<ChildNumber>().is_err(), "{bad:?} parsed");
        }
        // 2^31 written out is out of range for a bare index.
        assert!("2147483648".parse::<ChildNumber>().is_err());
    }

    #[test]
    fn path_round_trips_through_its_text_form() {
        for s in ["m", "m/0", "m/0'", "m/44'/7767'/0'/0/0", "m/2147483647'/1/2147483647"] {
            let path: DerivationPath = s.parse().unwrap();
            assert_eq!(path.to_string(), s, "round trip failed for {s}");
        }
    }

    #[test]
    fn path_accepts_alternate_hardened_markers() {
        let a: DerivationPath = "m/44'/7767'/0'".parse().unwrap();
        let b: DerivationPath = "m/44h/7767h/0h".parse().unwrap();
        let c: DerivationPath = "m/44H/7767H/0H".parse().unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a.to_string(), "m/44'/7767'/0'");
    }

    #[test]
    fn path_requires_the_leading_m() {
        for bad in ["", "44'/0'", "/0", "n/0", "m/", "m/x", "m//0"] {
            assert!(bad.parse::<DerivationPath>().is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn path_helpers_match_bip44() {
        assert_eq!(DerivationPath::ferrum_account(0).unwrap().to_string(), "m/44'/7767'/0'");
        assert_eq!(DerivationPath::ferrum(1, 1, 9).unwrap().to_string(), "m/44'/7767'/1'/1/9");
        assert_eq!(COIN_TYPE, 7767);
        assert_eq!(DerivationPath::master().to_string(), "m");
        assert!(DerivationPath::master().is_empty());
        assert_eq!(DerivationPath::master().len(), 0);
        assert_eq!(
            DerivationPath::master().child(ChildNumber::hardened(3).unwrap()).to_string(),
            "m/3'"
        );
    }

    #[test]
    fn path_iteration() {
        let path: DerivationPath = "m/1/2'/3".parse().unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path.as_slice().len(), 3);
        let collected: Vec<u32> = path.into_iter().map(|c| c.index()).collect();
        assert_eq!(collected, vec![1, 2, 3]);
    }
}
