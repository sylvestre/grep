// This file is part of the uutils grep package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::{Config, RegexMode};
use memchr::memmem;
use uucore::error::UResult;

// The two engines expose the same surface: `CompiledPattern` plus
// `is_word_match`. Which one is compiled in is decided once, here, so the
// code below never has to care.
#[cfg_attr(feature = "oniguruma", path = "matcher/onig_engine.rs")]
#[cfg_attr(not(feature = "oniguruma"), path = "matcher/literal_engine.rs")]
mod engine;

use engine::{CompiledPattern, is_word_match};

pub struct Matcher<'a> {
    config: &'a Config<'a>,
    patterns: Vec<CompiledPattern>,
    /// One substring searcher per pattern, present only when *every* pattern is
    /// a plain literal that a raw byte search resolves exactly (see
    /// [`plain_literal`]). When set, a caller can decide a line matches by
    /// looking for any of these needles, bypassing the regex engine entirely.
    /// `None` as soon as a single pattern needs real regex evaluation.
    literal_searchers: Option<Vec<memmem::Finder<'static>>>,
}

impl<'a> Matcher<'a> {
    pub fn compile(config: &'a Config<'a>) -> UResult<Self> {
        let mut patterns = Vec::with_capacity(config.patterns.len());
        for raw in config.patterns {
            patterns.push(CompiledPattern::compile(raw, config)?);
        }

        // If we can reduce the whole pattern set to literal needles, keep a
        // searcher for each so the driver can take a bulk substring-scan path.
        let needles: Option<Vec<Vec<u8>>> = config
            .patterns
            .iter()
            .map(|p| plain_literal(p, config.ignore_case, config.regex_mode))
            .collect();
        let literal_searchers = needles.filter(|n| !n.is_empty()).map(|n| {
            n.iter()
                .map(|w| memmem::Finder::new(w).into_owned())
                .collect()
        });

        Ok(Self {
            config,
            patterns,
            literal_searchers,
        })
    }

    /// Per-pattern substring searchers, present only when the pattern set is a
    /// pure set of literals (no regex needed). Used by the searcher to scan a
    /// whole buffer at once instead of testing line by line.
    pub fn literal_searchers(&self) -> Option<&[memmem::Finder<'static>]> {
        self.literal_searchers.as_deref()
    }

    /// Decide whether `line` matches and return the positions to highlight.
    pub fn match_line(&self, line: &[u8]) -> Option<Vec<(usize, usize)>> {
        let mut any_seen = false;
        let mut any_selected = false;
        let positions: Vec<_> = MatchIter::new(&self.patterns, line)
            .filter(|&(start, end)| {
                any_seen = true;
                // Drop matches that don't span the whole line if `-x` was requested.
                if self.config.line_regexp && !(start == 0 && end == line.len()) {
                    return false;
                }
                // Drop matches that aren't word matches if `-w` was requested.
                if self.config.word_regexp && !is_word_match(line, start, end) {
                    return false;
                }
                any_selected = true;
                // Drop zero-length matches from the output.
                if start == end {
                    return false;
                }
                true
            })
            .collect();

        let raw_matched = if self.config.line_regexp || self.config.word_regexp {
            // -w / -x are authoritative once matches are filtered. Zero-length
            // matches can select a line even though there is no span to output.
            any_selected
        } else {
            any_seen
        };

        if raw_matched != self.config.invert_match {
            Some(positions)
        } else {
            None
        }
    }

    /// Cheap match check that doesn't enumerate positions.
    pub fn is_match(&self, line: &[u8]) -> Option<Vec<(usize, usize)>> {
        // `-w` / `-x` need positions to filter, so we fall back to `match_line`.
        let matched = if self.config.line_regexp || self.config.word_regexp {
            self.match_line(line).is_some()
        } else {
            let raw_matched = self.patterns.iter().any(|p| p.is_match(line));
            raw_matched != self.config.invert_match
        };
        matched.then(Vec::new)
    }
}

/// Streaming k-way merge over compiled patterns
struct MatchIter<'a> {
    cursors: Vec<Cursor<'a>>,
    /// End of the last emitted match.
    last_end: usize,
}

impl<'a> MatchIter<'a> {
    fn new(patterns: &'a [CompiledPattern], line: &'a [u8]) -> Self {
        Self {
            cursors: patterns
                .iter()
                .map(|pattern| {
                    let mut c = Cursor {
                        pattern,
                        line,
                        offset: 0,
                        pending: None,
                    };
                    c.refill();
                    c
                })
                .collect(),
            last_end: 0,
        }
    }
}

impl<'a> Iterator for MatchIter<'a> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        // Discard stale pendings that fall before the last emit.
        for cursor in &mut self.cursors {
            if matches!(cursor.pending, Some((s, _)) if s < self.last_end) {
                cursor.offset = self.last_end;
                cursor.refill();
            }
        }

        // Pick the leftmost pending.
        // Tie-break by largest end so POSIX leftmost-longest holds across
        // patterns too (e.g. `-e a -e ab` against `ab` emits `ab`).
        let best_idx = self
            .cursors
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.pending.map(|p| (i, p)))
            .min_by_key(|&(_, (s, e))| (s, std::cmp::Reverse(e)))
            .map(|(i, _)| i)?;

        let (start, end) = self.cursors[best_idx].pending.unwrap();
        self.cursors[best_idx].refill();
        self.last_end = end;
        Some((start, end))
    }
}

struct Cursor<'a> {
    pattern: &'a CompiledPattern,
    line: &'a [u8],
    /// Where the next `search_leftmost` call should start.
    offset: usize,
    /// Pre-fetched next match for this pattern.
    /// `None` once the pattern is exhausted.
    pending: Option<(usize, usize)>,
}

impl Cursor<'_> {
    fn refill(&mut self) {
        if self.offset > self.line.len() {
            self.pending = None;
            return;
        }
        let Some((start, leftmost_end)) = self.pattern.search_leftmost(self.line, self.offset)
        else {
            self.pending = None;
            return;
        };
        let end = self
            .pattern
            .longest_end_at(self.line, start)
            .unwrap_or(leftmost_end);
        // Advance the next search past the match we just found.
        // Zero-length matches need a +1 nudge to avoid spinning forever.
        self.offset = end.max(start + 1);
        self.pending = Some((start, end));
    }
}

/// Return the literal bytes of `pattern` when a raw byte-for-byte substring
/// search is *exactly* equivalent to matching it, otherwise `None`.
///
/// We accept only ASCII, case-sensitive needles. That keeps the byte search in
/// agreement with the regex engine on every possible input, including bytes that
/// are not valid UTF-8: an ASCII byte can never be part of a multi-byte sequence,
/// so its presence is unambiguous. In the regex modes we also require that no
/// byte could ever act as a metacharacter; under `-F` the text is literal as-is.
fn plain_literal(pattern: &str, ignore_case: bool, mode: RegexMode) -> Option<Vec<u8>> {
    if ignore_case || pattern.is_empty() || !pattern.is_ascii() {
        return None;
    }
    // Every byte that carries special meaning in any of our regex syntaxes.
    // A needle without these reads the same as a literal in Basic/Extended/Perl.
    const SPECIAL: &[u8] = b".*[]^$\\+?{}()|";
    let plain = mode == RegexMode::Fixed || !pattern.bytes().any(|b| SPECIAL.contains(&b));
    plain.then(|| pattern.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::plain_literal;
    use crate::RegexMode;

    fn lit(p: &str, ic: bool, mode: RegexMode) -> Option<Vec<u8>> {
        plain_literal(p, ic, mode)
    }

    #[test]
    fn fixed_mode_takes_any_ascii_verbatim() {
        // Under -F every byte is literal, even regex metacharacters.
        assert_eq!(lit("abc", false, RegexMode::Fixed), Some(b"abc".to_vec()));
        assert_eq!(lit("a.*b", false, RegexMode::Fixed), Some(b"a.*b".to_vec()));
        assert_eq!(lit("a+b", false, RegexMode::Fixed), Some(b"a+b".to_vec()));
    }

    #[test]
    fn regex_modes_accept_metacharacter_free_literals() {
        for mode in [RegexMode::Basic, RegexMode::Extended, RegexMode::Perl] {
            assert_eq!(lit("ing", false, mode), Some(b"ing".to_vec()));
            assert_eq!(lit("Hello123", false, mode), Some(b"Hello123".to_vec()));
        }
    }

    #[test]
    fn regex_modes_reject_anything_with_a_metacharacter() {
        for mode in [RegexMode::Basic, RegexMode::Extended, RegexMode::Perl] {
            for p in [
                "a.b", "a*", "[ab]", "^a", "a$", "a\\b", "a+", "a?", "(a)", "a|b", "a{2}",
            ] {
                assert_eq!(lit(p, false, mode), None, "pattern {p:?} in {mode:?}");
            }
        }
    }

    #[test]
    fn rejects_empty_case_insensitive_and_non_ascii() {
        assert_eq!(lit("", false, RegexMode::Fixed), None);
        assert_eq!(lit("abc", true, RegexMode::Fixed), None); // -i
        assert_eq!(lit("abc", true, RegexMode::Basic), None);
        assert_eq!(lit("café", false, RegexMode::Fixed), None); // non-ASCII
        assert_eq!(lit("naïve", false, RegexMode::Basic), None);
    }
}
