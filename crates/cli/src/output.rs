//! How a command's result reaches the terminal.
//!
//! CONTRACT §13.1 pins an output *shape*, not just a set of fields: every
//! command that a devnet script reads "prints the bare value as the **last
//! line of stdout**, so `| tail -1` works, with `--json` available for
//! structured output". `devnet/lib.sh`, `devnet/fork.sh` and
//! `devnet/ci-e2e.sh` all parse the CLI that way.
//!
//! So a command does not print. It returns a [`CommandOutput`] carrying three
//! views of the same answer — a JSON document, some human lines, and the one
//! bare value — and exactly one of two renderings reaches stdout:
//!
//! | `--json` | stdout |
//! |---|---|
//! | absent | the human lines, then the bare value on its own final line |
//! | present | the JSON document, pretty-printed, and nothing else |
//!
//! Keeping the choice in one place is what makes "the last line is the value"
//! testable rather than a convention every command has to remember.

use serde_json::{Value, json};

/// One command's answer, in every form it might be asked for.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CommandOutput {
    /// The machine-readable document, printed under `--json`.
    pub json: Value,
    /// Human-readable context lines, printed without `--json`.
    pub human: Vec<String>,
    /// The bare value, printed as the last line of stdout without `--json`.
    pub bare: Option<String>,
}

impl CommandOutput {
    /// An output with nothing in it. Used by commands whose whole effect is a
    /// side effect.
    #[must_use]
    pub fn empty() -> Self {
        CommandOutput { json: Value::Null, human: Vec::new(), bare: None }
    }

    /// An output whose bare value is `value` and whose JSON is
    /// `{"<key>": "<value>"}`.
    ///
    /// The overwhelmingly common shape: `wallet address`, `wallet send`,
    /// `chain stateroot` and `block hash` are all one labelled scalar.
    #[must_use]
    pub fn scalar(key: &str, value: impl Into<String>) -> Self {
        let value = value.into();
        CommandOutput { json: json!({ key: value }), human: Vec::new(), bare: Some(value) }
    }

    /// An output carrying a JSON document and no bare value.
    #[must_use]
    pub fn document(json: Value) -> Self {
        CommandOutput { json, human: Vec::new(), bare: None }
    }

    /// Add a human-readable line, shown only without `--json`.
    #[must_use]
    pub fn with_line(mut self, line: impl Into<String>) -> Self {
        self.human.push(line.into());
        self
    }

    /// Add a `label: value` line, shown only without `--json`.
    #[must_use]
    pub fn with_field(self, label: &str, value: impl std::fmt::Display) -> Self {
        self.with_line(format!("{label:<18}{value}"))
    }

    /// Replace the JSON document.
    #[must_use]
    pub fn with_json(mut self, json: Value) -> Self {
        self.json = json;
        self
    }

    /// Replace the bare final line.
    #[must_use]
    pub fn with_bare(mut self, bare: impl Into<String>) -> Self {
        self.bare = Some(bare.into());
        self
    }

    /// Render for stdout.
    ///
    /// Returns the text *without* a trailing newline; the caller adds one, so
    /// an empty rendering prints nothing at all rather than a blank line.
    ///
    /// # Errors
    ///
    /// Never in practice: the only failure is serialising a `Value`, which
    /// cannot fail for a document that is already a `Value`. A failure is
    /// reported rather than panicked on.
    pub fn render(&self, json: bool) -> Result<String, serde_json::Error> {
        if json {
            return serde_json::to_string_pretty(&self.json);
        }
        let mut lines = self.human.clone();
        if let Some(bare) = &self.bare {
            lines.push(bare.clone());
        }
        Ok(lines.join("\n"))
    }

    /// Print the rendering to stdout, adding a newline unless it is empty.
    ///
    /// # Errors
    ///
    /// Propagates a serialisation failure; a closed stdout is ignored, because
    /// `| tail -1` closes the pipe as soon as it has what it wants and that is
    /// not an error the operator needs to see.
    pub fn print(&self, json: bool) -> Result<(), serde_json::Error> {
        let text = self.render(json)?;
        if !text.is_empty() {
            // A broken pipe here means the reader stopped, e.g. `| head -1`.
            // Reporting it would turn a successful command into a failure.
            let _ = writeln_stdout(&text);
        }
        Ok(())
    }
}

/// Write one line to stdout, reporting rather than panicking on failure.
fn writeln_stdout(text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    writeln!(lock, "{text}")?;
    lock.flush()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_bare_value_is_the_last_line() {
        let out = CommandOutput::scalar("address", "rfer1qexample")
            .with_line("network: devnet")
            .with_line("index:   0");
        let text = out.render(false).unwrap();
        assert_eq!(text.lines().next_back(), Some("rfer1qexample"));
        assert_eq!(text.lines().count(), 3);
    }

    #[test]
    fn json_mode_prints_only_the_document() {
        let out = CommandOutput::scalar("address", "rfer1qexample").with_line("noise");
        let text = out.render(true).unwrap();
        assert!(!text.contains("noise"));
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["address"], "rfer1qexample");
    }

    #[test]
    fn an_empty_output_renders_to_nothing() {
        assert_eq!(CommandOutput::empty().render(false).unwrap(), "");
    }

    #[test]
    fn a_document_has_no_bare_line() {
        let out = CommandOutput::document(json!({"height": 7}));
        assert_eq!(out.render(false).unwrap(), "");
        assert!(out.render(true).unwrap().contains("\"height\": 7"));
    }

    #[test]
    fn fields_are_column_aligned() {
        let out = CommandOutput::empty().with_field("height", 12);
        assert_eq!(out.render(false).unwrap(), "height            12");
    }
}
