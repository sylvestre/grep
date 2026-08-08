// This file is part of the uutils grep package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Pattern matching backed by the oniguruma regex engine.
//!
//! Selected by the `oniguruma` feature; see [`super`] for the module switch.

use crate::{Config, RegexMode};
use onig::{RegexOptions, Region, SearchOptions, Syntax, SyntaxBehavior, SyntaxOperator};
use onig_sys::{
    ONIGERR_EMPTY_RANGE_IN_CHAR_CLASS, OnigEncCtype_ONIGENC_CTYPE_WORD, OnigEncodingUTF8,
};
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use uucore::error::{UResult, USimpleError};
use uucore::show_warning;

static ONIG_NEW_MUTEX: Mutex<()> = Mutex::new(());

/// Word-boundary check `-w`.
/// NOTE that `-w` does not check both sides, unlike `\b` in a regex.
/// Start/End-of-line count as non-words.
pub(super) fn is_word_match(line: &[u8], start: usize, end: usize) -> bool {
    // SAFETY: This code uses OnigEncodingType such that it can support other types of encodings in the future.
    unsafe {
        let mbc_to_code = OnigEncodingUTF8.mbc_to_code.unwrap_unchecked();
        let is_code_ctype = OnigEncodingUTF8.is_code_ctype.unwrap_unchecked();
        let line_end = line.as_ptr().add(line.len());

        if end < line.len() {
            let cp = mbc_to_code(line.as_ptr().add(end), line_end);
            if is_code_ctype(cp, OnigEncCtype_ONIGENC_CTYPE_WORD) != 0 {
                return false;
            }
        }

        if start > 0 {
            let left_adjust = OnigEncodingUTF8.left_adjust_char_head.unwrap_unchecked();
            let head = left_adjust(line.as_ptr(), line.as_ptr().add(start - 1));
            let cp = mbc_to_code(head, line_end);
            if is_code_ctype(cp, OnigEncCtype_ONIGENC_CTYPE_WORD) != 0 {
                return false;
            }
        }

        true
    }
}

pub(super) struct CompiledPattern {
    /// Default semantics. It's decently fast and used for searching.
    leftmost: OnigRegex,
    /// Compiled with `FIND_LONGEST`. If used for a search, it'll search the
    /// entire haystack to find the longest. This makes it unsuitable for searching,
    /// but it's perfect for a second, anchored match pass for POSIX semantics.
    longest_anchored: OnigRegex,
}

impl CompiledPattern {
    pub(super) fn compile(pattern: &str, config: &Config) -> UResult<Self> {
        let mut syntax = *match config.regex_mode {
            RegexMode::Fixed => Syntax::asis(),
            RegexMode::Basic => Syntax::grep(),
            RegexMode::Extended => Syntax::gnu_regex(),
            RegexMode::Perl => Syntax::perl_ng(),
        };
        if config.regex_mode != RegexMode::Fixed {
            // GNU grep supports `{,n}` as an alias for `{0,n}`.
            syntax.enable_behavior(SyntaxBehavior::SYNTAX_BEHAVIOR_ALLOW_INTERVAL_LOW_ABBREV);
        }
        if matches!(config.regex_mode, RegexMode::Basic | RegexMode::Extended) {
            // GNU grep supports \` and \' as buffer anchors in BRE and ERE.
            syntax.enable_operators(SyntaxOperator::SYNTAX_OPERATOR_ESC_GNU_BUF_ANCHOR);
        }

        let mut normalized_pattern = None;
        let pattern = if config.regex_mode == RegexMode::Extended {
            if let Some((op, rest)) = strip_leading_repeat_operator(pattern) {
                show_warning!("{op} at start of expression");
                normalized_pattern = Some(rest.to_string());
            }
            normalized_pattern.as_deref().unwrap_or(pattern)
        } else {
            pattern
        };

        if config.regex_mode == RegexMode::Perl {
            // GNU grep supports `(?P<name>...)`.
            // Unfortunately, the onig crate defines the OP2 flag without the
            // necessary <<32 bit shift, so we need to hotpatch that here.
            const _: () =
                assert!(SyntaxOperator::SYNTAX_OPERATOR_QMARK_CAPITAL_P_NAME.bits() == 0x80000000);
            const FIXED: SyntaxOperator = SyntaxOperator::from_bits_retain(
                SyntaxOperator::SYNTAX_OPERATOR_QMARK_CAPITAL_P_NAME.bits() << 32,
            );
            syntax.enable_operators(FIXED);
        }

        let mut options = RegexOptions::REGEX_OPTION_NONE;
        if config.ignore_case {
            options |= RegexOptions::REGEX_OPTION_IGNORECASE;
        }
        // In GNU grep's Basic/Extended modes, `-z` makes newline ordinary data
        // for `.`, but PCRE keeps its existing non-DOTALL behavior. The GNU
        // `pcre-context` test documents this as current behavior until PCRE2.
        if config.null_data && matches!(config.regex_mode, RegexMode::Basic | RegexMode::Extended) {
            options |= RegexOptions::REGEX_OPTION_MULTILINE;
        }

        fn compile_with(
            pattern: &str,
            syntax: &Syntax,
            options: RegexOptions,
        ) -> UResult<OnigRegex> {
            OnigRegex::compile(pattern, syntax, options).map_err(|err| {
                // A reversed range like `[b-a]` is ONIGERR_EMPTY_RANGE_IN_CHAR_CLASS.
                // GNU grep reports it simply as "Invalid range end" (no pattern
                // echoed), so translate this code to match its diagnostic.
                let message = match err.code {
                    ONIGERR_EMPTY_RANGE_IN_CHAR_CLASS => "Invalid range end".to_string(),
                    _ => format!("invalid pattern \"{pattern}\": {}", err.message),
                };
                USimpleError::new(2, message)
            })
        }

        let leftmost = compile_with(pattern, &syntax, options)?;
        let longest_anchored = compile_with(
            pattern,
            &syntax,
            options | RegexOptions::REGEX_OPTION_FIND_LONGEST,
        )?;
        Ok(Self {
            leftmost,
            longest_anchored,
        })
    }

    /// Find the leftmost match starting at or after `offset`.
    pub(super) fn search_leftmost(&self, line: &[u8], offset: usize) -> Option<(usize, usize)> {
        let mut region = Region::new();
        self.leftmost.search(line, offset, Some(&mut region))?;
        region.pos(0)
    }

    /// Given a known leftmost start `start`, return the longest extent
    /// of a match anchored exactly there = POSIX leftmost-longest end.
    pub(super) fn longest_end_at(&self, line: &[u8], start: usize) -> Option<usize> {
        let mut region = Region::new();
        self.longest_anchored
            .match_at(line, start, Some(&mut region));
        region.pos(0).map(|(_, end)| end)
    }

    /// True if any match exists in `line` (including zero-length).
    pub(super) fn is_match(&self, line: &[u8]) -> bool {
        self.leftmost.search(line, 0, None).is_some()
    }
}

struct OnigRegex {
    raw: onig_sys::OnigRegex,
}

// SAFETY: Oniguruma compiled regexes are immutable after construction, and this
// wrapper owns and frees the raw pointer exactly once. This mirrors `onig::Regex`.
unsafe impl Send for OnigRegex {}
// SAFETY: Searches only read the compiled regex. Capture storage is caller-owned
// through `Region`, so sharing the compiled regex across threads is safe.
unsafe impl Sync for OnigRegex {}

impl OnigRegex {
    fn compile(pattern: &str, syntax: &Syntax, options: RegexOptions) -> Result<Self, OnigError> {
        let pattern = pattern.as_bytes();
        let mut raw = null_mut();
        let mut error = onig_sys::OnigErrorInfo {
            enc: null_mut(),
            par: null_mut(),
            par_end: null_mut(),
        };
        // SAFETY: This reads Oniguruma's process default case-folding bitset.
        let mut case_fold_flag = unsafe { onig_sys::onig_get_default_case_fold_flag() };
        if options.contains(RegexOptions::REGEX_OPTION_IGNORECASE) {
            case_fold_flag &= !onig_sys::INTERNAL_ONIGENC_CASE_FOLD_MULTI_CHAR;
        }

        let mut compile_info = onig_sys::OnigCompileInfo {
            num_of_elements: 5,
            pattern_enc: &raw mut OnigEncodingUTF8,
            target_enc: &raw mut OnigEncodingUTF8,
            syntax: syntax as *const Syntax as *mut Syntax as *mut onig_sys::OnigSyntaxType,
            option: options.bits(),
            case_fold_flag,
        };

        let _guard = ONIG_NEW_MUTEX.lock().unwrap();
        // SAFETY: `pattern` supplies a valid start/end pointer pair for the
        // duration of the call, and `compile_info` uses Oniguruma's built-in
        // UTF-8 encoding plus a syntax value borrowed from the safe wrapper.
        let result = unsafe {
            onig_sys::onig_new_deluxe(
                &mut raw,
                pattern.as_ptr(),
                pattern.as_ptr().add(pattern.len()),
                &mut compile_info,
                &mut error,
            )
        };
        if result == onig_sys::ONIG_NORMAL as i32 {
            Ok(Self { raw })
        } else {
            Err(OnigError::new(result, &error))
        }
    }

    fn search(&self, line: &[u8], offset: usize, region: Option<&mut Region>) -> Option<usize> {
        debug_assert!(offset <= line.len());
        // SAFETY: `offset` is bounded by `line.len()`, all byte pointers are
        // derived from `line`, and `region_ptr` preserves `onig::Region`'s
        // transparent representation over `OnigRegion`.
        let result = unsafe {
            let start = line.as_ptr().add(offset);
            let end = line.as_ptr().add(line.len());
            onig_sys::onig_search(
                self.raw,
                line.as_ptr(),
                end,
                start,
                end,
                region_ptr(region),
                SearchOptions::SEARCH_OPTION_NONE.bits(),
            )
        };
        onig_match_result(result)
    }

    fn match_at(&self, line: &[u8], offset: usize, region: Option<&mut Region>) -> Option<usize> {
        debug_assert!(offset <= line.len());
        // SAFETY: `offset` is bounded by `line.len()`, all byte pointers are
        // derived from `line`, and `region_ptr` preserves `onig::Region`'s
        // transparent representation over `OnigRegion`.
        let result = unsafe {
            let at = line.as_ptr().add(offset);
            onig_sys::onig_match(
                self.raw,
                line.as_ptr(),
                line.as_ptr().add(line.len()),
                at,
                region_ptr(region),
                SearchOptions::SEARCH_OPTION_NONE.bits(),
            )
        };
        onig_match_result(result)
    }
}

impl Drop for OnigRegex {
    fn drop(&mut self) {
        // SAFETY: `raw` was returned by a successful `onig_new_deluxe` call and
        // is owned by this wrapper.
        unsafe { onig_sys::onig_free(self.raw) }
    }
}

struct OnigError {
    code: i32,
    message: String,
}

impl OnigError {
    fn new(code: i32, info: *const onig_sys::OnigErrorInfo) -> Self {
        Self {
            code,
            message: onig_error_message(code, info),
        }
    }
}

fn region_ptr(region: Option<&mut Region>) -> *mut onig_sys::OnigRegion {
    region.map_or(null_mut(), |r| {
        r as *mut Region as *mut onig_sys::OnigRegion
    })
}

fn onig_match_result(result: i32) -> Option<usize> {
    if result >= 0 {
        Some(result as usize)
    } else if result == onig_sys::ONIG_MISMATCH {
        None
    } else {
        panic!(
            "Onig: Regex match error: {}",
            onig_error_message(result, null())
        );
    }
}

fn onig_error_message(code: i32, info: *const onig_sys::OnigErrorInfo) -> String {
    let mut buff = [0; onig_sys::ONIG_MAX_ERROR_MESSAGE_LEN as usize];
    let len = unsafe { onig_sys::onig_error_code_to_str(buff.as_mut_ptr(), code, info) };
    String::from_utf8_lossy(&buff[..len as usize]).into_owned()
}

fn strip_leading_repeat_operator(pattern: &str) -> Option<(&'static str, &str)> {
    match pattern.as_bytes().first()? {
        b'?' => Some(("?", &pattern[1..])),
        b'*' => Some(("*", &pattern[1..])),
        b'+' => Some(("+", &pattern[1..])),
        b'{' => strip_leading_interval_repeat(pattern).map(|rest| ("{...}", rest)),
        _ => None,
    }
}

fn strip_leading_interval_repeat(pattern: &str) -> Option<&str> {
    let close = pattern.as_bytes().iter().position(|&b| b == b'}')?;
    let body = &pattern[1..close];
    let is_interval = !body.is_empty()
        && body.bytes().all(|b| b.is_ascii_digit() || b == b',')
        && body.bytes().any(|b| b.is_ascii_digit());
    is_interval.then_some(&pattern[close + 1..])
}
