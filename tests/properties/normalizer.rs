// Property tests for the Normalizer
// Properties 3, 4, 5, 6

use mr_nope::normalizer::Normalizer;
use proptest::prelude::*;

// Feature: mr-nope, Property 3: Whitespace Normalization
// **Validates: Requirements 2.1**
// For any command string containing arbitrary sequences of spaces/tabs between tokens,
// after collapse_whitespace there are no consecutive spaces/tabs, and no leading/trailing whitespace.
proptest! {
    #[test]
    fn property_3_whitespace_normalization(input in "[ \\t\\w]{0,200}") {
        let result = Normalizer::collapse_whitespace(&input);

        // No leading whitespace
        prop_assert!(
            !result.starts_with(' ') && !result.starts_with('\t'),
            "Result has leading whitespace: {:?}",
            result
        );

        // No trailing whitespace
        prop_assert!(
            !result.ends_with(' ') && !result.ends_with('\t'),
            "Result has trailing whitespace: {:?}",
            result
        );

        // No consecutive spaces or tabs anywhere in the result
        let bytes = result.as_bytes();
        for i in 0..bytes.len().saturating_sub(1) {
            let current_is_ws = bytes[i] == b' ' || bytes[i] == b'\t';
            let next_is_ws = bytes[i + 1] == b' ' || bytes[i + 1] == b'\t';
            prop_assert!(
                !(current_is_ws && next_is_ws),
                "Found consecutive whitespace at position {} in: {:?}",
                i,
                result
            );
        }
    }
}

// Feature: mr-nope, Property 4: URL Decoding Round-Trip
// **Validates: Requirements 2.2, 2.3**
// For any ASCII string encoded with percent-encoding up to 3 levels,
// the normalizer decodes all sequences to produce the original characters.
proptest! {
    #[test]
    fn property_4_url_decoding_single_encode(original in "[a-zA-Z0-9 !/\\\\@#&=]{1,50}") {
        // Encode the string once with percent-encoding
        let encoded = percent_encode_string(&original);
        let (decoded, passes) = Normalizer::url_decode(&encoded);

        prop_assert_eq!(
            &decoded, &original,
            "Single-encoded string did not decode back to original.\nOriginal: {:?}\nEncoded: {:?}\nDecoded: {:?}",
            original, encoded, decoded
        );
        prop_assert!(passes >= 1, "Expected at least 1 pass for encoded input");
    }

    #[test]
    fn property_4_url_decoding_double_encode(original in "[a-zA-Z0-9 !/\\\\@#&=]{1,30}") {
        // Encode the string twice
        let encoded_once = percent_encode_string(&original);
        let encoded_twice = percent_encode_string(&encoded_once);
        let (decoded, passes) = Normalizer::url_decode(&encoded_twice);

        prop_assert_eq!(
            &decoded, &original,
            "Double-encoded string did not decode back to original.\nOriginal: {:?}\nEncoded twice: {:?}\nDecoded: {:?}",
            original, encoded_twice, decoded
        );
        prop_assert!(passes >= 2, "Expected at least 2 passes for double-encoded input");
    }

    #[test]
    fn property_4_url_decoding_triple_encode(original in "[a-zA-Z0-9 !/\\\\@#&=]{1,20}") {
        // Encode the string three times
        let encoded_once = percent_encode_string(&original);
        let encoded_twice = percent_encode_string(&encoded_once);
        let encoded_thrice = percent_encode_string(&encoded_twice);
        let (decoded, passes) = Normalizer::url_decode(&encoded_thrice);

        prop_assert_eq!(
            &decoded, &original,
            "Triple-encoded string did not decode back to original.\nOriginal: {:?}\nEncoded thrice: {:?}\nDecoded: {:?}",
            original, encoded_thrice, decoded
        );
        prop_assert_eq!(passes, 3, "Expected exactly 3 passes for triple-encoded input");
    }
}

// Feature: mr-nope, Property 5: Path Extraction with Any Separator
// **Validates: Requirements 2.5, 10.4**
// For any binary name and random path prefix using `/`, `\`, or both,
// extract_path extracts the binary name correctly.
proptest! {
    #[test]
    fn property_5_path_extraction_forward_slash(
        prefix_segments in prop::collection::vec("[a-zA-Z0-9._-]{1,10}", 1..5),
        binary_name in "[a-zA-Z0-9_-]{1,20}",
        args in "[a-zA-Z0-9 _-]{0,30}"
    ) {
        let path_prefix = prefix_segments.join("/");
        let input = if args.is_empty() {
            format!("{}/{}", path_prefix, binary_name)
        } else {
            format!("{}/{} {}", path_prefix, binary_name, args)
        };

        let result = Normalizer::extract_path(&input);

        let expected = if args.is_empty() {
            binary_name.clone()
        } else {
            format!("{} {}", binary_name, args)
        };

        prop_assert_eq!(
            &result, &expected,
            "Forward-slash path extraction failed.\nInput: {:?}\nExpected: {:?}\nGot: {:?}",
            input, expected, result
        );
    }

    #[test]
    fn property_5_path_extraction_backslash(
        prefix_segments in prop::collection::vec("[a-zA-Z0-9._-]{1,10}", 1..5),
        binary_name in "[a-zA-Z0-9_-]{1,20}",
        args in "[a-zA-Z0-9 _-]{0,30}"
    ) {
        let path_prefix = prefix_segments.join("\\");
        let input = if args.is_empty() {
            format!("{}\\{}", path_prefix, binary_name)
        } else {
            format!("{}\\{} {}", path_prefix, binary_name, args)
        };

        let result = Normalizer::extract_path(&input);

        let expected = if args.is_empty() {
            binary_name.clone()
        } else {
            format!("{} {}", binary_name, args)
        };

        prop_assert_eq!(
            &result, &expected,
            "Backslash path extraction failed.\nInput: {:?}\nExpected: {:?}\nGot: {:?}",
            input, expected, result
        );
    }

    #[test]
    fn property_5_path_extraction_mixed_separators(
        prefix_segments in prop::collection::vec("[a-zA-Z0-9._-]{1,10}", 2..5),
        separators in prop::collection::vec(prop::sample::select(vec!['/', '\\']), 2..5),
        binary_name in "[a-zA-Z0-9_-]{1,20}",
        args in "[a-zA-Z0-9 _-]{0,30}"
    ) {
        // Build a path with mixed separators
        let mut path = String::new();
        let num_segments = prefix_segments.len().min(separators.len() + 1);
        for i in 0..num_segments {
            path.push_str(&prefix_segments[i]);
            if i < separators.len() && i < num_segments - 1 {
                path.push(separators[i]);
            }
        }

        // Add the final separator and binary name
        let last_sep = separators.last().copied().unwrap_or('/');
        let input = if args.is_empty() {
            format!("{}{}{}", path, last_sep, binary_name)
        } else {
            format!("{}{}{} {}", path, last_sep, binary_name, args)
        };

        let result = Normalizer::extract_path(&input);

        let expected = if args.is_empty() {
            binary_name.clone()
        } else {
            format!("{} {}", binary_name, args)
        };

        prop_assert_eq!(
            &result, &expected,
            "Mixed-separator path extraction failed.\nInput: {:?}\nExpected: {:?}\nGot: {:?}",
            input, expected, result
        );
    }
}

// Feature: mr-nope, Property 6: Normalization Order Correctness
// **Validates: Requirements 2.6**
// For any command containing URL-encoded whitespace or path separators,
// verify that normalize produces the correct result (URL-decode first enables subsequent steps).
proptest! {
    #[test]
    fn property_6_normalization_order_encoded_path(
        prefix_segments in prop::collection::vec("[a-zA-Z0-9]{1,8}", 1..4),
        binary_name in "[a-zA-Z]{1,10}",
        subcommand in "[a-zA-Z]{1,10}"
    ) {
        // Create a command with URL-encoded path separators
        // e.g., "usr%2Fbin%2Fgit push" should decode to "usr/bin/git push"
        // then path-extract to "git push"
        let path_with_slashes = format!("{}/{}", prefix_segments.join("/"), binary_name);
        let encoded_path = path_with_slashes.replace("/", "%2F");
        let input = format!("{} {}", encoded_path, subcommand);

        let normalizer = Normalizer;
        let output = normalizer.normalize(&input);

        // The correct result: URL-decode first reveals the path separators,
        // then path extraction can extract the binary name
        prop_assert_eq!(
            &output.text,
            &format!("{} {}", binary_name, subcommand),
            "Normalization order incorrect for encoded path.\nInput: {:?}\nExpected: {:?}\nGot: {:?}",
            input, format!("{} {}", binary_name, subcommand), output.text
        );
    }

    #[test]
    fn property_6_normalization_order_encoded_whitespace(
        cmd in "[a-zA-Z]{1,10}",
        subcommand in "[a-zA-Z]{1,10}"
    ) {
        // Create a command with encoded whitespace between tokens
        // e.g., "git%20%20%20push" should decode to "git   push"
        // then whitespace collapse to "git push"
        let encoded_spaces = format!("{}%20%20%20{}", cmd, subcommand);

        let normalizer = Normalizer;
        let output = normalizer.normalize(&encoded_spaces);

        // The correct result: URL-decode reveals multiple spaces,
        // then whitespace collapse reduces them to a single space
        prop_assert_eq!(
            &output.text,
            &format!("{} {}", cmd, subcommand),
            "Normalization order incorrect for encoded whitespace.\nInput: {:?}\nExpected: {:?}\nGot: {:?}",
            encoded_spaces, format!("{} {}", cmd, subcommand), output.text
        );
    }

    #[test]
    fn property_6_normalization_order_encoded_backslash_path(
        prefix_segments in prop::collection::vec("[a-zA-Z0-9]{1,8}", 1..4),
        binary_name in "[a-zA-Z]{1,10}",
        subcommand in "[a-zA-Z]{1,10}"
    ) {
        // Create a command with URL-encoded backslash path separators
        // e.g., "dir%5Csubdir%5Cgit push" should decode to "dir\subdir\git push"
        // then path-extract to "git push"
        let path_with_backslashes = format!("{}\\{}", prefix_segments.join("\\"), binary_name);
        let encoded_path = path_with_backslashes.replace("\\", "%5C");
        let input = format!("{} {}", encoded_path, subcommand);

        let normalizer = Normalizer;
        let output = normalizer.normalize(&input);

        prop_assert_eq!(
            &output.text,
            &format!("{} {}", binary_name, subcommand),
            "Normalization order incorrect for encoded backslash path.\nInput: {:?}\nExpected: {:?}\nGot: {:?}",
            input, format!("{} {}", binary_name, subcommand), output.text
        );
    }
}

/// Helper: percent-encode a string (encodes all non-unreserved characters per RFC 3986).
/// For simplicity and test purposes, we encode every byte using %XX format.
fn percent_encode_string(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        encoded.push_str(&format!("%{:02X}", byte));
    }
    encoded
}
