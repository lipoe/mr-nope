// Mr. Nope - Normalizer module
// Handles URL decoding, whitespace collapsing, and path extraction.

use std::fmt;

/// Maximum number of URL-decoding passes to apply.
const MAX_DECODE_PASSES: u8 = 3;

/// The output of the normalization pipeline.
#[derive(Debug, Clone, PartialEq)]
pub struct NormalizedOutput {
    /// The normalized text after all transformations.
    pub text: String,
    /// The number of URL-decoding passes applied (0–3).
    pub decode_passes: u8,
}

/// Errors that can occur during normalization.
///
/// Note: In practice, the normalizer is designed to be best-effort —
/// invalid percent-encoding sequences pass through unchanged rather than
/// producing an error. This error type exists for cases where normalization
/// truly cannot proceed.
#[derive(Debug, Clone, PartialEq)]
pub enum NormalizationError {
    /// The input could not be normalized (reserved for future use).
    InvalidInput(String),
}

impl fmt::Display for NormalizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NormalizationError::InvalidInput(msg) => {
                write!(f, "normalization error: {}", msg)
            }
        }
    }
}

impl std::error::Error for NormalizationError {}

/// The Normalizer handles URL decoding, whitespace collapsing, and path extraction.
pub struct Normalizer;

impl Normalizer {
    /// Perform a single pass of percent-decoding.
    ///
    /// Decodes valid percent-encoded sequences (case-insensitive hex digits).
    /// Invalid sequences (e.g., `%ZZ`, `%G1`, or truncated `%` at end) pass through as-is.
    fn percent_decode_once(input: &str) -> String {
        let bytes = input.as_bytes();
        let len = bytes.len();
        let mut result = Vec::with_capacity(len);
        let mut i = 0;

        while i < len {
            if bytes[i] == b'%' && i + 2 < len {
                let hi = bytes[i + 1];
                let lo = bytes[i + 2];
                if let (Some(h), Some(l)) = (hex_digit_value(hi), hex_digit_value(lo)) {
                    result.push(h * 16 + l);
                    i += 3;
                } else {
                    // Invalid hex sequence — pass through as-is
                    result.push(bytes[i]);
                    i += 1;
                }
            } else {
                result.push(bytes[i]);
                i += 1;
            }
        }

        // The decoded output may not be valid UTF-8 (e.g., decoding arbitrary bytes).
        // We use lossy conversion to handle this gracefully.
        String::from_utf8(result).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
    }

    /// Perform iterative URL decoding up to MAX_DECODE_PASSES passes.
    ///
    /// Stops early if a pass produces no change (fully decoded).
    /// Returns the decoded string and the number of passes that produced changes.
    pub fn url_decode(input: &str) -> (String, u8) {
        let mut current = input.to_string();
        let mut passes: u8 = 0;

        for _ in 0..MAX_DECODE_PASSES {
            let decoded = Self::percent_decode_once(&current);
            if decoded == current {
                // No change — fully decoded, stop early.
                break;
            }
            passes += 1;
            current = decoded;
        }

        (current, passes)
    }

    /// Extract binary names from path-qualified references in the first token.
    ///
    /// If the first token (word before the first space) contains `/` or `\`,
    /// the final path segment is extracted as the base binary name and replaces
    /// the full path in the output. The rest of the command is preserved unchanged.
    ///
    /// Examples:
    /// - `/usr/bin/git push` → `git push`
    /// - `..\..\bin\git status` → `git status`
    /// - `./git commit` → `git commit`
    /// - `C:\Windows\System32\cmd /c dir` → `cmd /c dir`
    /// - `git push` → `git push` (no path separators, unchanged)
    pub fn extract_path(input: &str) -> String {
        if input.is_empty() {
            return String::new();
        }

        // Split into first token and the rest
        let (first_token, rest) = match input.find(' ') {
            Some(pos) => (&input[..pos], &input[pos..]),
            None => (input, ""),
        };

        // Check if the first token contains any path separator
        if !first_token.contains('/') && !first_token.contains('\\') {
            return input.to_string();
        }

        // Extract the final path segment (after the last separator)
        let binary_name = first_token
            .rsplit(|c| c == '/' || c == '\\')
            .next()
            .unwrap_or(first_token);

        // If the binary name is empty (e.g., trailing slash like "/usr/bin/"),
        // return the input unchanged to avoid producing an invalid result
        if binary_name.is_empty() {
            return input.to_string();
        }

        format!("{}{}", binary_name, rest)
    }

    /// Normalize a raw command string through the full pipeline:
    /// 1. URL-decode (iterative, max 3 passes)
    /// 2. Collapse whitespace (multiple spaces/tabs → single space, trim)
    /// 3. Extract binary names from path-qualified references
    pub fn normalize(&self, input: &str) -> NormalizedOutput {
        let (decoded, decode_passes) = Self::url_decode(input);
        let collapsed = Self::collapse_whitespace(&decoded);
        let text = Self::extract_path(&collapsed);
        NormalizedOutput {
            text,
            decode_passes,
        }
    }

    /// Collapse multiple consecutive spaces and tabs into a single space,
    /// and trim leading and trailing whitespace from the result.
    pub fn collapse_whitespace(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut in_whitespace = false;

        for ch in input.chars() {
            if ch == ' ' || ch == '\t' {
                if !in_whitespace {
                    in_whitespace = true;
                    result.push(' ');
                }
                // Otherwise skip — we already emitted one space for this run.
            } else {
                in_whitespace = false;
                result.push(ch);
            }
        }

        // Trim leading and trailing whitespace (the only whitespace remaining is single spaces).
        result.trim().to_string()
    }
}

/// Convert an ASCII byte representing a hex digit to its numeric value (0–15).
/// Returns None if the byte is not a valid hex digit.
fn hex_digit_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_encoding() {
        let (result, passes) = Normalizer::url_decode("hello world");
        assert_eq!(result, "hello world");
        assert_eq!(passes, 0); // No encoding found, no transformative passes
    }

    #[test]
    fn test_simple_percent_decode() {
        let (result, passes) = Normalizer::url_decode("git%20push");
        assert_eq!(result, "git push");
        assert_eq!(passes, 1);
    }

    #[test]
    fn test_case_insensitive_hex() {
        let (result, _) = Normalizer::url_decode("%2f"); // lowercase
        assert_eq!(result, "/");
        let (result, _) = Normalizer::url_decode("%2F"); // uppercase
        assert_eq!(result, "/");
        let (result, _) = Normalizer::url_decode("%2f%2F");
        assert_eq!(result, "//");
    }

    #[test]
    fn test_double_encoded() {
        // %2520 -> first pass decodes %25 to %, giving %20
        // second pass decodes %20 to space
        let (result, passes) = Normalizer::url_decode("%2520");
        assert_eq!(result, " ");
        assert_eq!(passes, 2);
    }

    #[test]
    fn test_triple_encoded() {
        // %252520 -> pass 1: %25 -> %, giving %2520
        // pass 2: %25 -> %, giving %20
        // pass 3: %20 -> space
        let (result, passes) = Normalizer::url_decode("%252520");
        assert_eq!(result, " ");
        assert_eq!(passes, 3);
    }

    #[test]
    fn test_quadruple_encoded_stops_at_3() {
        // %25252520 -> pass 1: %25 -> %, giving %252520
        // pass 2: %25 -> %, giving %2520
        // pass 3: %25 -> %, giving %20
        // stops at 3 passes, result is still %20 (partially decoded)
        let (result, passes) = Normalizer::url_decode("%25252520");
        assert_eq!(result, "%20");
        assert_eq!(passes, 3);
    }

    #[test]
    fn test_invalid_percent_encoding_passes_through() {
        let (result, passes) = Normalizer::url_decode("%ZZ");
        assert_eq!(result, "%ZZ");
        assert_eq!(passes, 0); // No valid encoding to decode
    }

    #[test]
    fn test_mixed_valid_and_invalid() {
        let (result, _) = Normalizer::url_decode("git%20push%ZZfoo");
        assert_eq!(result, "git push%ZZfoo");
    }

    #[test]
    fn test_truncated_percent_at_end() {
        let (result, _) = Normalizer::url_decode("hello%");
        assert_eq!(result, "hello%");
        let (result, _) = Normalizer::url_decode("hello%2");
        assert_eq!(result, "hello%2");
    }

    #[test]
    fn test_empty_input() {
        let (result, passes) = Normalizer::url_decode("");
        assert_eq!(result, "");
        assert_eq!(passes, 0);
    }

    #[test]
    fn test_multiple_encoded_chars() {
        let (result, _) = Normalizer::url_decode("%67%69%74%20%70%75%73%68");
        assert_eq!(result, "git push");
    }

    // --- collapse_whitespace tests ---

    #[test]
    fn test_collapse_no_extra_whitespace() {
        let result = Normalizer::collapse_whitespace("git push");
        assert_eq!(result, "git push");
    }

    #[test]
    fn test_collapse_multiple_spaces() {
        let result = Normalizer::collapse_whitespace("git   push");
        assert_eq!(result, "git push");
    }

    #[test]
    fn test_collapse_tabs() {
        let result = Normalizer::collapse_whitespace("git\t\tpush");
        assert_eq!(result, "git push");
    }

    #[test]
    fn test_collapse_mixed_spaces_and_tabs() {
        let result = Normalizer::collapse_whitespace("git \t \t push");
        assert_eq!(result, "git push");
    }

    #[test]
    fn test_collapse_trims_leading_whitespace() {
        let result = Normalizer::collapse_whitespace("   git push");
        assert_eq!(result, "git push");
    }

    #[test]
    fn test_collapse_trims_trailing_whitespace() {
        let result = Normalizer::collapse_whitespace("git push   ");
        assert_eq!(result, "git push");
    }

    #[test]
    fn test_collapse_trims_both_ends() {
        let result = Normalizer::collapse_whitespace("\t  git   push  \t");
        assert_eq!(result, "git push");
    }

    #[test]
    fn test_collapse_empty_input() {
        let result = Normalizer::collapse_whitespace("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_collapse_whitespace_only() {
        let result = Normalizer::collapse_whitespace("   \t\t   ");
        assert_eq!(result, "");
    }

    #[test]
    fn test_collapse_single_word() {
        let result = Normalizer::collapse_whitespace("git");
        assert_eq!(result, "git");
    }

    #[test]
    fn test_collapse_preserves_other_chars() {
        let result = Normalizer::collapse_whitespace("git  commit  -m  \"hello world\"");
        assert_eq!(result, "git commit -m \"hello world\"");
    }

    // --- extract_path tests ---

    #[test]
    fn test_extract_path_absolute_unix() {
        let result = Normalizer::extract_path("/usr/bin/git push");
        assert_eq!(result, "git push");
    }

    #[test]
    fn test_extract_path_absolute_unix_deep() {
        let result = Normalizer::extract_path("/usr/local/bin/git status");
        assert_eq!(result, "git status");
    }

    #[test]
    fn test_extract_path_relative_dot_slash() {
        let result = Normalizer::extract_path("./git commit");
        assert_eq!(result, "git commit");
    }

    #[test]
    fn test_extract_path_relative_parent() {
        let result = Normalizer::extract_path("../../bin/git log");
        assert_eq!(result, "git log");
    }

    #[test]
    fn test_extract_path_windows_backslash() {
        let result = Normalizer::extract_path("..\\..\\bin\\git push");
        assert_eq!(result, "git push");
    }

    #[test]
    fn test_extract_path_windows_full() {
        let result = Normalizer::extract_path("C:\\Windows\\System32\\cmd /c dir");
        assert_eq!(result, "cmd /c dir");
    }

    #[test]
    fn test_extract_path_mixed_separators() {
        let result = Normalizer::extract_path("C:\\Users/bin\\git status");
        assert_eq!(result, "git status");
    }

    #[test]
    fn test_extract_path_no_separator() {
        let result = Normalizer::extract_path("git push");
        assert_eq!(result, "git push");
    }

    #[test]
    fn test_extract_path_single_word_no_separator() {
        let result = Normalizer::extract_path("git");
        assert_eq!(result, "git");
    }

    #[test]
    fn test_extract_path_no_arguments() {
        let result = Normalizer::extract_path("/usr/bin/git");
        assert_eq!(result, "git");
    }

    #[test]
    fn test_extract_path_empty_input() {
        let result = Normalizer::extract_path("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_extract_path_trailing_slash() {
        // Trailing slash means empty binary name — return input unchanged
        let result = Normalizer::extract_path("/usr/bin/");
        assert_eq!(result, "/usr/bin/");
    }

    #[test]
    fn test_extract_path_preserves_rest_of_command() {
        let result = Normalizer::extract_path("/usr/bin/git commit -m \"initial commit\"");
        assert_eq!(result, "git commit -m \"initial commit\"");
    }

    #[test]
    fn test_extract_path_only_affects_first_token() {
        // Path separators in arguments should not be affected
        let result = Normalizer::extract_path("/usr/bin/cat /etc/passwd");
        assert_eq!(result, "cat /etc/passwd");
    }

    // --- normalize pipeline tests ---

    #[test]
    fn test_normalize_simple_command() {
        let normalizer = Normalizer;
        let output = normalizer.normalize("git push");
        assert_eq!(output.text, "git push");
        assert_eq!(output.decode_passes, 0);
    }

    #[test]
    fn test_normalize_url_encoded_space() {
        // URL decode first: "git%20push" → "git push", then whitespace collapse (no-op), then path extract (no-op)
        let normalizer = Normalizer;
        let output = normalizer.normalize("git%20push");
        assert_eq!(output.text, "git push");
        assert_eq!(output.decode_passes, 1);
    }

    #[test]
    fn test_normalize_url_encoded_path() {
        // URL decode: "%2Fusr%2Fbin%2Fgit push" → "/usr/bin/git push"
        // Whitespace collapse: no-op
        // Path extract: "/usr/bin/git push" → "git push"
        let normalizer = Normalizer;
        let output = normalizer.normalize("%2Fusr%2Fbin%2Fgit push");
        assert_eq!(output.text, "git push");
        assert_eq!(output.decode_passes, 1);
    }

    #[test]
    fn test_normalize_encoded_whitespace_then_collapse() {
        // URL decode: "git%20%20%20push" → "git   push"
        // Whitespace collapse: "git   push" → "git push"
        // Path extract: no-op
        let normalizer = Normalizer;
        let output = normalizer.normalize("git%20%20%20push");
        assert_eq!(output.text, "git push");
        assert_eq!(output.decode_passes, 1);
    }

    #[test]
    fn test_normalize_double_encoded() {
        // Double-encoded space: "%2520" → pass 1: "%20" → pass 2: " "
        // So "git%2520push" → "git push" after 2 passes
        // Whitespace collapse: no-op (single space)
        // Path extract: no-op
        let normalizer = Normalizer;
        let output = normalizer.normalize("git%2520push");
        assert_eq!(output.text, "git push");
        assert_eq!(output.decode_passes, 2);
    }

    #[test]
    fn test_normalize_pipeline_order_matters() {
        // This test verifies that URL-decode happens BEFORE path-extract.
        // Input: "%2Fusr%2Fbin%2Fgit%20push"
        // Correct order (URL-decode first):
        //   decode → "/usr/bin/git push" → collapse → "/usr/bin/git push" → path-extract → "git push"
        // Wrong order (path-extract first):
        //   path-extract would see no path separators (they're encoded) → unchanged
        let normalizer = Normalizer;
        let output = normalizer.normalize("%2Fusr%2Fbin%2Fgit%20push");
        assert_eq!(output.text, "git push");
        assert_eq!(output.decode_passes, 1);
    }

    #[test]
    fn test_normalize_pipeline_whitespace_before_path() {
        // Verifies that whitespace collapse happens BEFORE path-extract.
        // Input after decode: "/usr/bin/git   push"
        // Correct: collapse → "/usr/bin/git push" → path-extract → "git push"
        let normalizer = Normalizer;
        let output = normalizer.normalize("/usr/bin/git   push");
        assert_eq!(output.text, "git push");
        assert_eq!(output.decode_passes, 0);
    }

    #[test]
    fn test_normalize_empty_input() {
        let normalizer = Normalizer;
        let output = normalizer.normalize("");
        assert_eq!(output.text, "");
        assert_eq!(output.decode_passes, 0);
    }

    #[test]
    fn test_normalize_whitespace_only() {
        let normalizer = Normalizer;
        let output = normalizer.normalize("   \t\t   ");
        assert_eq!(output.text, "");
        assert_eq!(output.decode_passes, 0);
    }

    #[test]
    fn test_normalize_encoded_backslash_path() {
        // URL decode: "..%5C..%5Cbin%5Cgit push" → "..\\..\\bin\\git push"
        // Whitespace collapse: no-op
        // Path extract: "..\\..\\bin\\git push" → "git push"
        let normalizer = Normalizer;
        let output = normalizer.normalize("..%5C..%5Cbin%5Cgit push");
        assert_eq!(output.text, "git push");
        assert_eq!(output.decode_passes, 1);
    }
}
