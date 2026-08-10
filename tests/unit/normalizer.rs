// Unit tests for the Normalizer
// Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6

use mr_nope::normalizer::Normalizer;

// --- URL Decoding Tests ---

/// Test 1: URL-encoded `git push` decodes to `git push`
#[test]
fn url_encoded_git_push_decodes_correctly() {
    let normalizer = Normalizer;
    let output = normalizer.normalize("git%20push");
    assert_eq!(output.text, "git push");
    assert_eq!(output.decode_passes, 1);
}

/// Test 2: Double-encoded path separator decodes through two passes
#[test]
fn double_encoded_path_separator_decodes_in_two_passes() {
    let normalizer = Normalizer;
    // %252F -> pass 1: %2F -> pass 2: /
    // So "%252Fusr%252Fbin%252Fgit push" decodes to "/usr/bin/git push" in 2 passes
    // Then path extraction gives "git push"
    let output = normalizer.normalize("%252Fusr%252Fbin%252Fgit push");
    assert_eq!(output.text, "git push");
    assert_eq!(output.decode_passes, 2);
}

/// Test 3: Triple-encoded space needs three passes
#[test]
fn triple_encoded_space_needs_three_passes() {
    let normalizer = Normalizer;
    // %252520 -> pass 1: %2520 -> pass 2: %20 -> pass 3: " "
    let output = normalizer.normalize("git%252520push");
    assert_eq!(output.text, "git push");
    assert_eq!(output.decode_passes, 3);
}

/// Test 4: Quadruple-encoded (4+ levels) stops at 3 passes, partially decoded
#[test]
fn quadruple_encoded_stops_at_three_passes() {
    let normalizer = Normalizer;
    // %25252520 -> pass 1: %252520 -> pass 2: %2520 -> pass 3: %20
    // Stops at 3 passes, result still contains %20 (partially decoded)
    let output = normalizer.normalize("git%25252520push");
    assert_eq!(output.text, "git%20push");
    assert_eq!(output.decode_passes, 3);
}

/// Test 5: Invalid %ZZ sequences pass through unchanged
#[test]
fn invalid_percent_encoding_passes_through_unchanged() {
    let normalizer = Normalizer;
    let output = normalizer.normalize("%ZZ");
    assert_eq!(output.text, "%ZZ");
    assert_eq!(output.decode_passes, 0);
}

/// Test 6: Mixed valid/invalid encoding
#[test]
fn mixed_valid_and_invalid_encoding() {
    let normalizer = Normalizer;
    let output = normalizer.normalize("git%20push%ZZfoo");
    assert_eq!(output.text, "git push%ZZfoo");
    assert_eq!(output.decode_passes, 1);
}

// --- Whitespace Collapsing Tests ---

/// Test 7: Multiple spaces collapse to single space
#[test]
fn whitespace_collapsing_multiple_spaces() {
    let normalizer = Normalizer;
    let output = normalizer.normalize("git   push");
    assert_eq!(output.text, "git push");
}

/// Test 8: Tabs collapse to single space
#[test]
fn whitespace_collapsing_tabs() {
    let normalizer = Normalizer;
    let output = normalizer.normalize("git\t\tpush");
    assert_eq!(output.text, "git push");
}

/// Test 9: Leading/trailing whitespace trimmed
#[test]
fn leading_and_trailing_whitespace_trimmed() {
    let normalizer = Normalizer;
    let output = normalizer.normalize("  \tgit push\t  ");
    assert_eq!(output.text, "git push");
}

// --- Path Extraction Tests ---

/// Test 10: Unix absolute path extraction
#[test]
fn path_extraction_unix_absolute() {
    let normalizer = Normalizer;
    let output = normalizer.normalize("/usr/bin/git push");
    assert_eq!(output.text, "git push");
}

/// Test 11: Relative backslash path extraction
#[test]
fn path_extraction_relative_backslash() {
    let normalizer = Normalizer;
    let output = normalizer.normalize("..\\..\\bin\\git status");
    assert_eq!(output.text, "git status");
}

/// Test 12: Mixed separators path extraction
#[test]
fn path_extraction_mixed_separators() {
    let normalizer = Normalizer;
    let output = normalizer.normalize("C:\\Users/bin\\git log");
    assert_eq!(output.text, "git log");
}

// --- Full Pipeline Tests ---

/// Test 13: Full pipeline — URL-encoded path decodes and extracts correctly
#[test]
fn full_pipeline_url_encoded_path() {
    let normalizer = Normalizer;
    // URL decode: "%2Fusr%2Fbin%2Fgit%20push" -> "/usr/bin/git push"
    // Whitespace collapse: no-op
    // Path extract: "/usr/bin/git push" -> "git push"
    let output = normalizer.normalize("%2Fusr%2Fbin%2Fgit%20push");
    assert_eq!(output.text, "git push");
    assert_eq!(output.decode_passes, 1);
}

// --- Edge Cases ---

/// Test 14: Empty input returns empty
#[test]
fn empty_input_returns_empty() {
    let normalizer = Normalizer;
    let output = normalizer.normalize("");
    assert_eq!(output.text, "");
    assert_eq!(output.decode_passes, 0);
}

/// Test 15: Whitespace-only input returns empty string after trim
#[test]
fn whitespace_only_input_returns_empty() {
    let normalizer = Normalizer;
    let output = normalizer.normalize("   \t\t   ");
    assert_eq!(output.text, "");
    assert_eq!(output.decode_passes, 0);
}

/// Test 16: Truncated percent at end of string passes through
#[test]
fn truncated_percent_at_end_passes_through() {
    let normalizer = Normalizer;
    let output = normalizer.normalize("hello%");
    assert_eq!(output.text, "hello%");
    assert_eq!(output.decode_passes, 0);
}
