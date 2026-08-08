// This file is part of the uutils grep package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Literal-only stand-in for the oniguruma engine, selected when the crate is
//! built without the `oniguruma` feature; see [`super`] for the module switch.
//!
//! Only patterns that a raw byte search resolves exactly are accepted. Anything
//! needing a real regex engine is rejected at compile time with exit code 2.

use super::plain_literal;
use crate::Config;
use memchr::memmem;
use uucore::error::{UResult, USimpleError};

/// Word-boundary check `-w`, the counterpart of the oniguruma engine's.
///
/// There is no encoding table to consult here, so the check is ASCII-only.
/// That is enough for the literal patterns this engine accepts, which are
/// themselves ASCII.
pub(super) fn is_word_match(line: &[u8], start: usize, end: usize) -> bool {
    fn is_ascii_word(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_'
    }

    if end < line.len() && is_ascii_word(line[end]) {
        return false;
    }
    if start > 0 && is_ascii_word(line[start - 1]) {
        return false;
    }
    true
}

pub(super) struct CompiledPattern {
    needle: Vec<u8>,
    finder: memmem::Finder<'static>,
}

impl CompiledPattern {
    pub(super) fn compile(pattern: &str, config: &Config) -> UResult<Self> {
        let Some(needle) = plain_literal(pattern, config.ignore_case, config.regex_mode) else {
            return Err(USimpleError::new(
                2,
                "this build supports ASCII literal patterns only; rebuild with the `oniguruma` feature for full regex support".to_string(),
            ));
        };
        let finder = memmem::Finder::new(&needle).into_owned();
        Ok(Self { needle, finder })
    }

    /// Find the leftmost match starting at or after `offset`.
    pub(super) fn search_leftmost(&self, line: &[u8], offset: usize) -> Option<(usize, usize)> {
        self.finder.find(&line[offset..]).map(|relative| {
            let start = offset + relative;
            (start, start + self.needle.len())
        })
    }

    /// Given a known leftmost start `start`, return the longest extent of a
    /// match anchored exactly there.
    pub(super) fn longest_end_at(&self, line: &[u8], start: usize) -> Option<usize> {
        line.get(start..start + self.needle.len())
            .is_some_and(|bytes| bytes == self.needle.as_slice())
            .then_some(start + self.needle.len())
    }

    /// True if any match exists in `line`.
    pub(super) fn is_match(&self, line: &[u8]) -> bool {
        self.finder.find(line).is_some()
    }
}
