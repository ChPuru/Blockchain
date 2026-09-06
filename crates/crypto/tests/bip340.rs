//! The official BIP-340 test vectors, all 19 of them.
//!
//! Source: `bip-0340/test-vectors.csv` from the BIP repository. Every value
//! below is **quoted** from that file — none is self-generated. The same table
//! ships inside `k256`'s own test suite, which is where this copy was taken
//! from, so the two are byte-identical by construction.
//!
//! The table is split the way the BIP splits it:
//!
//! - indices 0-3: signing vectors. A secret key, an aux value and a 32-byte
//!   message must produce an exact signature, and that signature must verify.
//! - indices 4-14: verification vectors, mostly *invalid*. These are the
//!   interesting ones: a public key off the curve, `has_even_y(R)` false, a
//!   negated message, a negated `s`, `sG - eP` infinite, `r` not an
//!   x-coordinate, `r` equal to the field size, `s` equal to the group order,
//!   and a public key above the field size.
//! - indices 15-18: signing vectors with **variable-length** messages (0, 1,
//!   17 and 100 bytes). Ferrum's [`SecretKey::sign`] fixes the message at a
//!   32-byte `Hash32` — every Ferrum signature is over a `tagged_hash`
//!   digest — so those four cannot be expressed through the Ferrum API. They
//!   are run against `k256::schnorr` directly, which is the exact primitive
//!   `SecretKey::sign` calls, so they still pin the dependency's conformance.

#![allow(clippy::unwrap_used)]

use ferrum_crypto::{CryptoError, PublicKey, SecretKey, Signature};
use ferrum_types::Hash32;

fn bytes(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("test vector is valid hex")
}

fn array32(hex_str: &str) -> [u8; 32] {
    bytes(hex_str).try_into().expect("test vector is 32 bytes")
}

fn array64(hex_str: &str) -> [u8; 64] {
    bytes(hex_str).try_into().expect("test vector is 64 bytes")
}

/// A BIP-340 signing vector (indices 0-3).
struct SignVector {
    index: u8,
    secret_key: &'static str,
    public_key: &'static str,
    aux_rand: &'static str,
    message: &'static str,
    signature: &'static str,
}

/// BIP-340 test vectors 0-3, quoted from the BIP.
const SIGN_VECTORS: &[SignVector] = &[
    SignVector {
        index: 0,
        secret_key: "0000000000000000000000000000000000000000000000000000000000000003",
        public_key: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        aux_rand: "0000000000000000000000000000000000000000000000000000000000000000",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
    },
    SignVector {
        index: 1,
        secret_key: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        aux_rand: "0000000000000000000000000000000000000000000000000000000000000001",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
    },
    SignVector {
        index: 2,
        secret_key: "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
        public_key: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        aux_rand: "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
        message: "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
        signature: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
    },
    // "test fails if msg is reduced modulo p or n"
    SignVector {
        index: 3,
        secret_key: "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
        public_key: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
        aux_rand: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        message: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        signature: "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
    },
];

/// How Ferrum rejects an invalid vector.
///
/// The BIP itself only says valid or invalid; this finer split is Ferrum's own
/// error classification, and pinning it stops a refactor from turning a
/// "malformed signature" into a silent "verification failed" (or the reverse),
/// which is the difference between banning a peer and merely dropping a
/// message.
#[derive(Debug, PartialEq, Eq)]
enum Expected {
    /// The signature verifies.
    Valid,
    /// The public key bytes are not an x-only point.
    BadKey,
    /// `r` is not a non-zero field element, or `s` is not in `1..n`.
    BadSignatureEncoding,
    /// Well-formed, but the equation does not hold.
    BadSignature,
}

/// A BIP-340 verification vector (indices 4-14).
struct VerifyVector {
    index: u8,
    public_key: &'static str,
    message: &'static str,
    signature: &'static str,
    valid: bool,
    expected: Expected,
    reason: &'static str,
}

/// BIP-340 test vectors 4-14, quoted from the BIP with its own comments.
const VERIFY_VECTORS: &[VerifyVector] = &[
    VerifyVector {
        index: 4,
        public_key: "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
        message: "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
        signature: "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
        valid: true,
        expected: Expected::Valid,
        reason: "a valid signature whose r has many leading zero bytes",
    },
    VerifyVector {
        index: 5,
        public_key: "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        valid: false,
        expected: Expected::BadKey,
        reason: "public key not on the curve",
    },
    VerifyVector {
        index: 6,
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
        valid: false,
        expected: Expected::BadSignature,
        reason: "has_even_y(R) is false",
    },
    VerifyVector {
        index: 7,
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
        valid: false,
        expected: Expected::BadSignature,
        reason: "negated message",
    },
    VerifyVector {
        index: 8,
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
        valid: false,
        expected: Expected::BadSignature,
        reason: "negated s value",
    },
    VerifyVector {
        index: 9,
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
        valid: false,
        expected: Expected::BadSignatureEncoding,
        reason: "sG - eP is infinite, with has_even_y(inf) true and x(inf) 0",
    },
    VerifyVector {
        index: 10,
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
        valid: false,
        expected: Expected::BadSignature,
        reason: "sG - eP is infinite, with has_even_y(inf) true and x(inf) 1",
    },
    VerifyVector {
        index: 11,
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        valid: false,
        expected: Expected::BadSignature,
        reason: "sig[0:32] is not an X coordinate on the curve",
    },
    VerifyVector {
        index: 12,
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        valid: false,
        expected: Expected::BadSignatureEncoding,
        reason: "sig[0:32] is equal to the field size",
    },
    VerifyVector {
        index: 13,
        public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        valid: false,
        expected: Expected::BadSignatureEncoding,
        reason: "sig[32:64] is equal to the curve order",
    },
    VerifyVector {
        index: 14,
        public_key: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        valid: false,
        expected: Expected::BadKey,
        reason: "public key exceeds the field size",
    },
];

/// A BIP-340 variable-length-message signing vector (indices 15-18).
struct ExtSignVector {
    index: u8,
    /// Hex of one unit of the message.
    message: &'static str,
    /// How many times that unit repeats. Vector 18 is 100 copies of `0x99`;
    /// spelling 200 hex characters out by hand is exactly how a test vector
    /// silently becomes wrong, so the repetition is expressed as a number.
    repeat: usize,
    signature: &'static str,
}

impl ExtSignVector {
    fn message_bytes(&self) -> Vec<u8> {
        bytes(self.message).repeat(self.repeat)
    }
}

/// The shared secret key of vectors 15-18, quoted from the BIP.
const EXT_SECRET_KEY: &str = "0340034003400340034003400340034003400340034003400340034003400340";

/// BIP-340 test vectors 15-18, quoted from the BIP. All use `aux = 0`.
const EXT_SIGN_VECTORS: &[ExtSignVector] = &[
    ExtSignVector {
        index: 15,
        message: "",
        repeat: 1,
        signature: "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63",
    },
    ExtSignVector {
        index: 16,
        message: "11",
        repeat: 1,
        signature: "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
    },
    ExtSignVector {
        index: 17,
        message: "0102030405060708090A0B0C0D0E0F1011",
        repeat: 1,
        signature: "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
    },
    ExtSignVector {
        index: 18,
        message: "99",
        repeat: 100,
        signature: "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
    },
];

#[test]
fn there_are_nineteen_vectors() {
    let total = SIGN_VECTORS.len() + VERIFY_VECTORS.len() + EXT_SIGN_VECTORS.len();
    assert_eq!(total, 19, "BIP-340 publishes exactly 19 vectors");

    // The indices must be 0..=18 with no gaps and no repeats.
    let mut indices: Vec<u8> = SIGN_VECTORS.iter().map(|v| v.index).collect();
    indices.extend(VERIFY_VECTORS.iter().map(|v| v.index));
    indices.extend(EXT_SIGN_VECTORS.iter().map(|v| v.index));
    indices.sort_unstable();
    assert_eq!(indices, (0u8..19).collect::<Vec<u8>>());
}

#[test]
fn sign_vectors_produce_the_exact_published_signature() {
    for v in SIGN_VECTORS {
        let sk = SecretKey::from_bytes(&array32(v.secret_key))
            .unwrap_or_else(|e| panic!("vector {}: secret key rejected: {e}", v.index));
        let expected_pk = PublicKey::from_bytes(&array32(v.public_key))
            .unwrap_or_else(|e| panic!("vector {}: public key rejected: {e}", v.index));

        assert_eq!(sk.public_key(), expected_pk, "vector {}: wrong public key", v.index);

        let msg = Hash32::from_bytes(array32(v.message));
        let sig = sk.sign(&msg, &array32(v.aux_rand));
        assert_eq!(
            sig,
            Signature::from_bytes(array64(v.signature)),
            "vector {}: wrong signature",
            v.index
        );

        assert_eq!(expected_pk.verify(&msg, &sig), Ok(()), "vector {}: did not verify", v.index);
    }
}

#[test]
fn sign_vector_zero_matches_sign_deterministic() {
    // Vector 0 has aux = 0, which is exactly what `sign_deterministic` uses.
    let v = &SIGN_VECTORS[0];
    let sk = SecretKey::from_bytes(&array32(v.secret_key)).unwrap();
    let msg = Hash32::from_bytes(array32(v.message));
    assert_eq!(sk.sign_deterministic(&msg), Signature::from_bytes(array64(v.signature)));
}

#[test]
fn verify_vectors_are_accepted_or_rejected_exactly_as_published() {
    for v in VERIFY_VECTORS {
        let pk = PublicKey::from_bytes(&array32(v.public_key));
        let sig = Signature::from_bytes(array64(v.signature));
        let msg = Hash32::from_bytes(array32(v.message));

        let accepted = match pk {
            Ok(pk) => pk.verify(&msg, &sig).is_ok(),
            // A key that will not even parse can never accept a signature.
            Err(_) => false,
        };

        assert_eq!(accepted, v.valid, "vector {}: {} — wrong verdict", v.index, v.reason);
    }
}

#[test]
fn every_vector_fails_in_the_documented_way() {
    for v in VERIFY_VECTORS {
        let msg = Hash32::from_bytes(array32(v.message));
        let sig = Signature::from_bytes(array64(v.signature));

        let outcome = match PublicKey::from_bytes(&array32(v.public_key)) {
            Err(CryptoError::InvalidPublicKey) => Expected::BadKey,
            Err(other) => panic!("vector {}: unexpected key error {other}", v.index),
            Ok(pk) => match pk.verify(&msg, &sig) {
                Ok(()) => Expected::Valid,
                Err(CryptoError::InvalidSignatureEncoding) => Expected::BadSignatureEncoding,
                Err(CryptoError::VerificationFailed) => Expected::BadSignature,
                Err(other) => panic!("vector {}: unexpected verify error {other}", v.index),
            },
        };

        assert_eq!(outcome, v.expected, "vector {}: {}", v.index, v.reason);
        assert_eq!(
            outcome == Expected::Valid,
            v.valid,
            "vector {}: classification disagrees with the BIP verdict",
            v.index
        );
    }
}

#[test]
fn variable_length_message_vectors_hold_at_the_k256_layer() {
    // Ferrum always signs a 32-byte `Hash32`, so vectors 15-18 cannot go
    // through `SecretKey::sign`. They are checked here against the exact
    // primitive that `SecretKey::sign` calls, so the dependency's BIP-340
    // conformance is still pinned by this crate's test suite.
    let sk = k256::schnorr::SigningKey::from_bytes(&bytes(EXT_SECRET_KEY)).unwrap();
    let aux = [0u8; 32];
    for v in EXT_SIGN_VECTORS {
        let msg = v.message_bytes();
        let sig = sk
            .sign_raw(&msg, &aux)
            .unwrap_or_else(|e| panic!("vector {}: signing failed: {e}", v.index));
        assert_eq!(
            sig.to_bytes(),
            array64(v.signature),
            "vector {}: wrong signature for a {}-byte message",
            v.index,
            msg.len()
        );
    }
}

#[test]
fn the_variable_length_vectors_have_the_published_message_lengths() {
    let lengths: Vec<usize> = EXT_SIGN_VECTORS.iter().map(|v| v.message_bytes().len()).collect();
    assert_eq!(lengths, vec![0, 1, 17, 100], "vectors 15-18 are 0, 1, 17 and 100 bytes");
    assert!(EXT_SIGN_VECTORS[3].message_bytes().iter().all(|b| *b == 0x99));
}

#[test]
fn every_valid_vector_also_passes_batch_verification() {
    let mut items = Vec::new();
    for v in SIGN_VECTORS {
        items.push((
            PublicKey::from_bytes(&array32(v.public_key)).unwrap(),
            Hash32::from_bytes(array32(v.message)),
            Signature::from_bytes(array64(v.signature)),
        ));
    }
    for v in VERIFY_VECTORS.iter().filter(|v| v.valid) {
        items.push((
            PublicKey::from_bytes(&array32(v.public_key)).unwrap(),
            Hash32::from_bytes(array32(v.message)),
            Signature::from_bytes(array64(v.signature)),
        ));
    }
    assert_eq!(items.len(), 5, "4 signing vectors plus vector 4");
    assert_eq!(ferrum_crypto::verify_batch(&items), Ok(()));
}

#[test]
fn a_single_invalid_vector_poisons_the_batch() {
    let good = &SIGN_VECTORS[1];
    let bad = VERIFY_VECTORS.iter().find(|v| v.index == 7).unwrap();
    let items = vec![
        (
            PublicKey::from_bytes(&array32(good.public_key)).unwrap(),
            Hash32::from_bytes(array32(good.message)),
            Signature::from_bytes(array64(good.signature)),
        ),
        (
            PublicKey::from_bytes(&array32(bad.public_key)).unwrap(),
            Hash32::from_bytes(array32(bad.message)),
            Signature::from_bytes(array64(bad.signature)),
        ),
    ];
    assert_eq!(
        ferrum_crypto::verify_batch(&items),
        Err(CryptoError::BatchVerificationFailed { index: 1 })
    );
}
