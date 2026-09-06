//! How a keystore passphrase is obtained — and the one way it never is.
//!
//! **A passphrase is never a command-line argument.** On every operating
//! system the argument vector of a running process is readable by other
//! processes (`/proc/<pid>/cmdline`, `ps auxww`, `Get-CimInstance Win32_Process`),
//! and on most shells it lands in the history file as well. There is therefore
//! no `--passphrase` flag anywhere in `chain-cli`, and adding one later would
//! be a security regression, not a convenience.
//!
//! Three sources remain, in the order they are consulted:
//!
//! 1. `--passphrase-file <FILE>` — the file's contents, with one trailing
//!    newline removed. This is what a systemd unit or a CI job uses.
//! 2. `--prompt-passphrase` — a prompt on the terminal.
//! 3. Nothing, which means the **empty passphrase**.
//!
//! The empty default is deliberate and it is what makes devnet automation
//! possible: `devnet/fork.sh` runs `chain-cli wallet new --output …` with its
//! stdout and stderr redirected but its **stdin still attached to the
//! operator's terminal**. A CLI that prompted by default would hang there
//! forever, with the prompt swallowed by the redirect — a hang with no visible
//! cause. Prompting is therefore opt-in, and `wallet open` additionally falls
//! back to a prompt when the empty passphrase is refused and a terminal is
//! actually available.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::{CliError, CliResult};

/// Where a passphrase should come from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PassphraseSource {
    /// A file holding the passphrase.
    pub file: Option<PathBuf>,
    /// Whether to prompt on the terminal.
    pub prompt: bool,
}

impl PassphraseSource {
    /// The source for "no flags given": the empty passphrase.
    #[must_use]
    pub fn empty() -> Self {
        PassphraseSource::default()
    }

    /// Read a file.
    #[must_use]
    pub fn from_file(path: impl Into<PathBuf>) -> Self {
        PassphraseSource { file: Some(path.into()), prompt: false }
    }

    /// Ask the terminal.
    #[must_use]
    pub fn prompting() -> Self {
        PassphraseSource { file: None, prompt: true }
    }

    /// Resolve to the passphrase itself.
    ///
    /// `confirm` asks for the passphrase twice and compares, which is only
    /// wanted when a *new* keystore is being written: getting it wrong there
    /// is unrecoverable, and getting it wrong when opening simply fails.
    ///
    /// # Errors
    ///
    /// [`CliError::Io`] when the file cannot be read, and
    /// [`CliError::Invalid`] when a confirmation does not match.
    pub fn resolve(&self, confirm: bool) -> CliResult<Zeroizing<String>> {
        if let Some(path) = &self.file {
            return read_passphrase_file(path);
        }
        if self.prompt {
            let first = prompt_line("Passphrase: ")?;
            if confirm {
                let second = prompt_line("Confirm passphrase: ")?;
                if first.as_str() != second.as_str() {
                    return Err(CliError::invalid(
                        "passphrase",
                        "<hidden>",
                        "the two entries did not match",
                    ));
                }
            }
            return Ok(first);
        }
        Ok(Zeroizing::new(String::new()))
    }

    /// Whether a prompt on the terminal is still available as a fallback.
    ///
    /// False when a file was given (the operator was explicit), when a prompt
    /// already happened, or when stdin is not a terminal — a redirected stdin
    /// would read EOF and turn a wrong-passphrase error into a confusing one.
    #[must_use]
    pub fn can_fall_back_to_prompt(&self) -> bool {
        self.file.is_none() && !self.prompt && std::io::stdin().is_terminal()
    }
}

/// Read a passphrase from a file, trimming exactly one trailing newline.
///
/// Only one, and only at the end: a passphrase may legitimately contain
/// leading spaces, and `printf 'hunter2' > pass.txt` and
/// `echo hunter2 > pass.txt` must yield the same passphrase.
///
/// # Errors
///
/// [`CliError::Io`] when the file cannot be read, and [`CliError::Invalid`]
/// when it does not hold UTF-8.
pub fn read_passphrase_file(path: &Path) -> CliResult<Zeroizing<String>> {
    let raw = std::fs::read(path).map_err(|e| CliError::io(path, e))?;
    let mut text = String::from_utf8(raw).map_err(|_| {
        CliError::invalid("--passphrase-file", path.display().to_string(), "not valid UTF-8")
    })?;
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    Ok(Zeroizing::new(text))
}

/// Prompt on stderr and read one line from stdin.
///
/// The prompt goes to **stderr** so that stdout stays exactly the value the
/// devnet scripts read with `| tail -1`.
///
/// There is no terminal echo suppression here: doing it portably needs a
/// platform console crate, and this workspace introduces no dependency it does
/// not need. The prompt says so, so nobody is surprised.
///
/// # Errors
///
/// [`CliError::BareIo`] when the terminal cannot be read, and
/// [`CliError::Invalid`] on end of input.
pub fn prompt_line(prompt: &str) -> CliResult<Zeroizing<String>> {
    let mut stderr = std::io::stderr();
    write!(stderr, "{prompt}")?;
    stderr.flush()?;

    let mut line = Zeroizing::new(String::new());
    let read = std::io::stdin().read_line(&mut line)?;
    if read == 0 {
        return Err(CliError::invalid("passphrase", "<empty>", "end of input on stdin"));
    }
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn no_flags_means_the_empty_passphrase() {
        let resolved = PassphraseSource::empty().resolve(false).unwrap();
        assert_eq!(resolved.as_str(), "");
    }

    #[test]
    fn a_file_loses_exactly_one_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pass");
        std::fs::write(&path, b"  hunter2 \n").unwrap();
        let resolved = PassphraseSource::from_file(&path).resolve(false).unwrap();
        assert_eq!(resolved.as_str(), "  hunter2 ");
    }

    #[test]
    fn a_file_loses_a_windows_line_ending_too() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pass");
        std::fs::write(&path, b"hunter2\r\n").unwrap();
        let resolved = PassphraseSource::from_file(&path).resolve(false).unwrap();
        assert_eq!(resolved.as_str(), "hunter2");
    }

    #[test]
    fn a_missing_passphrase_file_names_itself() {
        let err = PassphraseSource::from_file("D:/definitely/not/here").resolve(false).unwrap_err();
        assert!(err.to_string().contains("not/here"), "{err}");
    }

    #[test]
    fn an_explicit_file_never_falls_back_to_a_prompt() {
        assert!(!PassphraseSource::from_file("x").can_fall_back_to_prompt());
        assert!(!PassphraseSource::prompting().can_fall_back_to_prompt());
    }
}
