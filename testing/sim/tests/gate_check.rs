//! Does the determinism gate actually work?
//!
//! SPEC §8 says non-determinism is kept out of the state transition
//! "**mechanically**, not by review": `clippy.toml` declares the offending
//! methods and types disallowed, and `scripts/check-invariants.sh` greps the
//! consensus crates. A gate nobody has ever seen fire is an assumption, not a
//! control — so this file checks the gate itself.
//!
//! Three things are asserted:
//!
//! 1. **The gate is configured.** `clippy.toml` names `SystemTime::now`,
//!    `Instant::now`, `HashMap`, `HashSet`, `f32` and `f64`; the invariant
//!    script greps `crates/chain/src`, `crates/consensus/src`,
//!    `crates/script/src` and `crates/storage/src` for the clock and the RNG,
//!    and the whole tree for floats, unbounded queues, unfinished-code macros
//!    and `unsafe`.
//! 2. **The patterns catch what they claim to.** The script's alternations are
//!    re-implemented here as a small scanner, and each alternative is run
//!    against a synthetic offending line. A pattern that matched nothing would
//!    otherwise sit green forever.
//! 3. **The gate is passing today, and would fail tomorrow.** The same scanner
//!    is run over the real consensus sources (it must find nothing) and then
//!    over a synthetic executor with `SystemTime::now()` spliced into it (it
//!    must find exactly that line). That second half is the point of the file:
//!    it demonstrates, in code, that deliberately reintroducing a
//!    non-deterministic construct into the executor turns the gate red.
//!
//! The scanner is written out rather than shelling out to `grep`, because the
//! test must behave identically on a machine with no `bash` — which is the
//! machine this project is developed on.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

/// `clippy.toml`, embedded at compile time so a missing file is a build error
/// rather than a skipped test.
const CLIPPY_TOML: &str = include_str!("../../../clippy.toml");

/// `scripts/check-invariants.sh`, embedded for the same reason.
const INVARIANTS_SH: &str = include_str!("../../../scripts/check-invariants.sh");

/// The directories the determinism section of the invariant script greps.
const DETERMINISM_PATHS: [&str; 4] =
    ["crates/chain/src", "crates/consensus/src", "crates/script/src", "crates/storage/src"];

/// The clock constructs that may never appear in the state-transition path.
const CLOCK_ALTERNATIVES: [&str; 4] = ["SystemTime::now", "Instant::now", "Utc::now", "Local::now"];

/// The randomness constructs that may never appear in it either.
const RNG_ALTERNATIVES: [&str; 3] = ["thread_rng", "OsRng", "random()"];

// The next five needles are assembled with `concat!` rather than written out.
// `scripts/check-invariants.sh` greps `crates` **and** `testing` for exactly
// these strings, so spelling them literally here would make this file the very
// violation it exists to detect — a test that breaks the gate it guards. The
// concatenation is resolved at compile time and costs nothing at run time.
const UNBOUNDED_CHANNEL: &str = concat!("unbounded", "_channel");
const TODO_MACRO: &str = concat!("todo", "!(");
const UNIMPLEMENTED_MACRO: &str = concat!("unimplemented", "!(");
const UNSAFE_BLOCK: &str = concat!("unsafe", " {");
const UNSAFE_FN: &str = concat!("unsafe", " fn ");

// The alternations `scripts/check-invariants.sh` carries, split for the same
// reason. Each is compared against the script verbatim, so a pattern that is
// edited there without being understood here fails this test.
const SCRIPT_CLOCK_PATTERN: &str = "SystemTime::now|Instant::now|Utc::now|Local::now";
const SCRIPT_RNG_PATTERN: &str = concat!("thread_rng|OsRng|random", "\\(\\)");
const SCRIPT_QUEUE_PATTERN: &str = concat!("unbounded", "_channel|unbounded\\(\\)");
const SCRIPT_FLOAT_PATTERN: &str = "\\bf32\\b|\\bf64\\b";
const SCRIPT_STUB_PATTERN: &str = concat!("todo", "!\\(|unimplemented!\\(");

/// The repository root.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("testing/sim is two levels below the root")
        .to_path_buf()
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// One hit: the file, the 1-based line number and the line itself.
#[derive(Debug, PartialEq, Eq)]
struct Hit {
    file: String,
    line: usize,
    text: String,
}

/// Whether `line` is a comment, using the same filter the shell script applies
/// (`grep -v '^\s*//'`).
fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

/// Whether `needle` occurs in `haystack` as a whole word.
///
/// This is the `\b…\b` half of the script's patterns, which is what stops
/// `\bf64\b` from matching `buf64` or `f64x2`.
fn contains_word(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut from = 0usize;
    while let Some(offset) = haystack.get(from..).and_then(|s| s.find(needle)) {
        let start = from + offset;
        let end = start + needle.len();
        let before_ok = start == 0 || !is_word_byte(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_word_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Scan `text` for any of `needles`, skipping comment lines.
///
/// `word` selects between the `\b…\b` and plain-substring flavours the script
/// uses.
fn scan_text(name: &str, text: &str, needles: &[&str], word: bool) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if is_comment(line) {
            continue;
        }
        for needle in needles {
            let found = if word { contains_word(line, needle) } else { line.contains(needle) };
            if found {
                hits.push(Hit {
                    file: name.to_owned(),
                    line: index + 1,
                    text: line.trim().to_owned(),
                });
                break;
            }
        }
    }
    hits
}

/// Scan every `.rs` file under `dir`.
fn scan_dir(root: &Path, rel: &str, needles: &[&str], word: bool) -> Vec<Hit> {
    let dir = root.join(rel);
    assert!(dir.is_dir(), "{rel} must exist for the gate to grep it");
    let mut hits = Vec::new();
    for file in rust_files(&dir) {
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        let name = file.strip_prefix(root).unwrap_or(&file).display().to_string();
        hits.extend(scan_text(&name, &text, needles, word));
    }
    hits
}

// ---------------------------------------------------------------------------
// 1. The gate is configured
// ---------------------------------------------------------------------------

#[test]
fn clippy_toml_disallows_the_named_methods() {
    assert!(CLIPPY_TOML.contains("disallowed-methods"));
    for path in ["std::time::SystemTime::now", "std::time::Instant::now"] {
        assert!(CLIPPY_TOML.contains(path), "clippy.toml must disallow {path}");
    }
    assert!(CLIPPY_TOML.contains("std::collections::HashMap::iter"));
    assert!(CLIPPY_TOML.contains("std::collections::HashSet::iter"));
}

#[test]
fn clippy_toml_disallows_the_named_types() {
    assert!(CLIPPY_TOML.contains("disallowed-types"));
    for path in ["std::collections::HashMap", "std::collections::HashSet"] {
        assert!(CLIPPY_TOML.contains(path), "clippy.toml must disallow {path}");
    }
    // Quoted, so that a substring of some other identifier cannot satisfy the
    // assertion by accident.
    assert!(CLIPPY_TOML.contains("path = \"f32\""), "clippy.toml must disallow f32");
    assert!(CLIPPY_TOML.contains("path = \"f64\""), "clippy.toml must disallow f64");
}

#[test]
fn clippy_toml_says_why_each_entry_exists() {
    // A disallowed entry with no reason is one a future contributor deletes to
    // make a build green.
    let reasons = CLIPPY_TOML.matches("reason =").count();
    assert!(reasons >= 8, "every disallowed entry needs a reason, found {reasons}");
    assert!(CLIPPY_TOML.contains("BlockCtx"), "the clock entry must name where time comes from");
    assert!(CLIPPY_TOML.contains("BTreeMap"), "the map entries must name the replacement");
}

#[test]
fn the_invariant_script_greps_the_consensus_crates() {
    for path in DETERMINISM_PATHS {
        assert!(
            INVARIANTS_SH.contains(path),
            "check-invariants.sh must grep {path} for the determinism seam"
        );
    }
    // The executor itself must be inside one of those directories.
    let root = repo_root();
    assert!(root.join("crates/chain/src/apply.rs").is_file(), "the executor must exist");
}

#[test]
fn the_invariant_script_greps_the_right_patterns() {
    let expected = [
        SCRIPT_CLOCK_PATTERN,
        SCRIPT_RNG_PATTERN,
        SCRIPT_QUEUE_PATTERN,
        SCRIPT_FLOAT_PATTERN,
        SCRIPT_STUB_PATTERN,
    ];
    for pattern in expected {
        assert!(
            INVARIANTS_SH.contains(pattern),
            "check-invariants.sh must carry the pattern {pattern}"
        );
    }
    // The alternations must list exactly the alternatives this file scans for,
    // so the two cannot drift apart.
    for needle in CLOCK_ALTERNATIVES {
        assert!(SCRIPT_CLOCK_PATTERN.contains(needle), "the script must look for {needle}");
    }
    for needle in ["thread_rng", "OsRng"] {
        assert!(SCRIPT_RNG_PATTERN.contains(needle), "the script must look for {needle}");
    }
    assert!(SCRIPT_QUEUE_PATTERN.contains(UNBOUNDED_CHANNEL));
    assert!(SCRIPT_FLOAT_PATTERN.contains("f32") && SCRIPT_FLOAT_PATTERN.contains("f64"));
    // It attempts to ignore comment lines, so that a "do not use
    // SystemTime::now" note does not fail the build. See
    // `the_scripts_comment_filter_never_reaches_grep_rn_output` for what that
    // filter actually does.
    assert!(INVARIANTS_SH.contains("grep -v '^\\s*//'"));
    // And it must scan the workspace, not only the consensus crates, for the
    // rules that apply everywhere.
    assert!(INVARIANTS_SH.contains("crates testing"));
}

// ---------------------------------------------------------------------------
// 2. The patterns catch what they claim to
// ---------------------------------------------------------------------------

#[test]
fn every_clock_alternative_matches_an_offending_line() {
    for needle in CLOCK_ALTERNATIVES {
        let source = format!("fn apply() {{\n    let t = {needle}();\n}}\n");
        let hits = scan_text("synthetic.rs", &source, &CLOCK_ALTERNATIVES, false);
        assert_eq!(hits.len(), 1, "the pattern must catch {needle}");
        assert_eq!(hits[0].line, 2);
    }
}

#[test]
fn every_rng_alternative_matches_an_offending_line() {
    for needle in RNG_ALTERNATIVES {
        let source = format!("fn apply() {{\n    let r = {needle};\n}}\n");
        let hits = scan_text("synthetic.rs", &source, &RNG_ALTERNATIVES, false);
        assert_eq!(hits.len(), 1, "the pattern must catch {needle}");
    }
}

#[test]
fn the_float_pattern_uses_word_boundaries() {
    // `\bf64\b` must catch a float and must not catch an identifier that
    // happens to contain those three characters.
    assert!(contains_word("let x: f64 = 1.0;", "f64"));
    assert!(contains_word("value as f32", "f32"));
    assert!(!contains_word("let buf64 = [];", "f64"));
    assert!(!contains_word("struct Xf64y;", "f64"));
    assert!(!contains_word("let f64x = 1;", "f64"));
}

#[test]
fn comment_lines_are_ignored_exactly_as_the_script_ignores_them() {
    let source = "// SystemTime::now is forbidden here\n    //! and here too\nlet t = 1;\n";
    assert!(scan_text("doc.rs", source, &CLOCK_ALTERNATIVES, false).is_empty());
    assert!(is_comment("   // a comment"));
    assert!(is_comment("//! a doc comment"));
    assert!(!is_comment("let x = 1; // trailing"));
}

// ---------------------------------------------------------------------------
// 3. The gate passes today and would fail tomorrow
// ---------------------------------------------------------------------------

#[test]
fn the_consensus_crates_contain_no_clock_today() {
    let root = repo_root();
    for rel in DETERMINISM_PATHS {
        let hits = scan_dir(&root, rel, &CLOCK_ALTERNATIVES, false);
        assert!(hits.is_empty(), "wall clock in the state-transition path: {hits:#?}");
    }
}

#[test]
fn the_consensus_crates_contain_no_rng_today() {
    let root = repo_root();
    for rel in ["crates/chain/src", "crates/consensus/src", "crates/script/src"] {
        let hits = scan_dir(&root, rel, &RNG_ALTERNATIVES, false);
        assert!(hits.is_empty(), "randomness in the state-transition path: {hits:#?}");
    }
}

#[test]
fn no_crate_contains_a_float() {
    let root = repo_root();
    let hits = scan_dir(&root, "crates", &["f32", "f64"], true);
    assert!(hits.is_empty(), "a float is a chain split waiting to happen: {hits:#?}");
}

#[test]
fn no_unbounded_queue_anywhere() {
    let root = repo_root();
    for rel in ["crates", "testing"] {
        let hits = scan_dir(&root, rel, &[UNBOUNDED_CHANNEL], false);
        assert!(hits.is_empty(), "an unbounded queue is an OOM instead of a load-shed: {hits:#?}");
    }
}

#[test]
fn no_unfinished_code_anywhere() {
    let root = repo_root();
    for rel in ["crates", "testing"] {
        let hits = scan_dir(&root, rel, &[TODO_MACRO, UNIMPLEMENTED_MACRO], false);
        assert!(hits.is_empty(), "unfinished code: {hits:#?}");
    }
}

#[test]
fn no_unsafe_anywhere() {
    let root = repo_root();
    for rel in ["crates", "testing"] {
        let hits = scan_dir(&root, rel, &[UNSAFE_BLOCK, UNSAFE_FN], false);
        assert!(hits.is_empty(), "the workspace forbids it: {hits:#?}");
    }
}

#[test]
fn the_simulator_itself_iterates_no_hash_map() {
    // The harness is part of the determinism story: a `HashMap` here would
    // make the golden state-root file unreproducible even with a correct
    // executor.
    let root = repo_root();
    let hits = scan_dir(&root, "testing/sim/src", &["HashMap", "HashSet"], true);
    assert!(hits.is_empty(), "the simulator must use BTreeMap/BTreeSet: {hits:#?}");
}

#[test]
fn splicing_a_clock_into_the_executor_would_turn_the_gate_red() {
    // The gate proved. Take the real executor, splice in the exact line a
    // careless change would add, and run the same scanner that reported the
    // file clean a moment ago.
    let root = repo_root();
    let executor = root.join("crates/chain/src/apply.rs");
    let clean = std::fs::read_to_string(&executor).expect("the executor is readable");
    assert!(
        scan_text("apply.rs", &clean, &CLOCK_ALTERNATIVES, false).is_empty(),
        "the executor must be clean before the experiment means anything"
    );

    let tampered = clean.replace(
        "pub fn apply_block(",
        "fn wall_clock_seconds() -> u64 {\n    \
         std::time::SystemTime::now().elapsed().map(|d| d.as_secs()).unwrap_or(0)\n}\n\n\
         pub fn apply_block(",
    );
    assert_ne!(tampered, clean, "the splice must have applied");

    let hits = scan_text("apply.rs", &tampered, &CLOCK_ALTERNATIVES, false);
    assert_eq!(hits.len(), 1, "the gate must catch the spliced clock, got {hits:#?}");
    assert!(hits[0].text.contains("SystemTime::now"));

    // The same is true of a float and of a HashMap.
    let floated = clean
        .replace("pub fn apply_block(", "fn ratio() -> f64 {\n    1.0\n}\n\npub fn apply_block(");
    assert_eq!(scan_text("apply.rs", &floated, &["f32", "f64"], true).len(), 1);

    let mapped = clean.replace(
        "pub fn apply_block(",
        "fn cache() -> std::collections::HashMap<u64, u64> {\n    \
         std::collections::HashMap::new()\n}\n\npub fn apply_block(",
    );
    assert_eq!(scan_text("apply.rs", &mapped, &["HashMap"], true).len(), 2);

    // Nothing was written: the experiment is entirely in memory.
    assert_eq!(std::fs::read_to_string(&executor).unwrap(), clean);
}

#[test]
fn the_scripts_comment_filter_never_reaches_grep_rn_output() {
    // A finding about the harness rather than about consensus, recorded here
    // instead of being left to be rediscovered.
    //
    // `check-invariants.sh` pipes `grep -rnE <pattern> <paths>` into
    // `grep -v '^\s*//'`, intending to drop comment lines. But `-rn` prefixes
    // every line with `path:line:`, so a line that *is* a comment does not
    // begin with `//` by the time the filter sees it, and the filter matches
    // nothing. A doc comment that merely mentions a forbidden token is
    // therefore reported as a violation.
    //
    // The failure direction is conservative — a false positive, never a false
    // negative — so the gate is still sound. It is worth recording because a
    // check that cries wolf is a check somebody eventually deletes.
    let as_grep_prints_it = "crates/rpc/src/types/rpc.rs:70:/// names `f64` here";
    assert!(
        !as_grep_prints_it.trim_start().starts_with("//"),
        "the filter cannot see a comment behind the path prefix"
    );
    // This file's own scanner filters the line itself, which does work.
    let hits = scan_text("rpc.rs", "/// names `f64` here\nlet x = 1;\n", &["f32", "f64"], true);
    assert!(hits.is_empty(), "a mention in a comment is not a float");
}

#[test]
fn the_scanner_finds_a_clock_in_a_directory_walk_too() {
    // The per-file check above proves the pattern; this proves the walk that
    // feeds it, using a directory the harness creates and removes.
    let dir = tempfile::tempdir().expect("temp dir");
    let nested = dir.path().join("src").join("deep");
    std::fs::create_dir_all(&nested).expect("mkdir");
    std::fs::write(nested.join("clean.rs"), "pub fn f() -> u64 { 1 }\n").expect("write");
    std::fs::write(
        nested.join("dirty.rs"),
        "pub fn f() -> u64 {\n    let t = std::time::Instant::now();\n    0\n}\n",
    )
    .expect("write");

    let hits = scan_dir(dir.path(), "src", &CLOCK_ALTERNATIVES, false);
    assert_eq!(hits.len(), 1, "the walk must reach nested files: {hits:#?}");
    assert!(hits[0].file.ends_with("dirty.rs"));
    assert_eq!(hits[0].line, 2);
}
