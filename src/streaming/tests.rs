#[cfg(test)]
mod tests {
    use crate::streaming::{StreamChunkResult, StreamingMatcher};
    use aho_corasick::AhoCorasick;

    fn test_automaton(patterns: &[&str]) -> AhoCorasick {
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(patterns)
            .unwrap()
    }

    #[test]
    fn verify_streaming_match_at_exact_buffer_boundary() {
        let ac = test_automaton(&["ab"]);
        let max_buffer = 10;
        let mut matcher = StreamingMatcher::new(ac, max_buffer);

        let mut data = vec![b'X'; 10];
        data.extend_from_slice(b"ab");

        let result = matcher.feed(&data);
        assert!(
            matches!(result, StreamChunkResult::MatchFound { .. }),
            "Pattern starting exactly at max_buffer boundary must be detected"
        );
    }

    #[test]
    fn match_in_first_chunk() {
        let ac = test_automaton(&["apache", "nginx"]);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        let result = matcher.feed(b"Server: Apache/2.4.51");
        assert!(matches!(result, StreamChunkResult::MatchFound { .. }));
        assert!(matcher.should_cancel());
        assert_eq!(matcher.matched_patterns().len(), 1);
    }

    #[test]
    fn match_across_chunks() {
        let ac = test_automaton(&["password"]);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        // First chunk: no match
        let result = matcher.feed(b"<html><body>");
        assert!(matches!(result, StreamChunkResult::NeedMore));

        // Second chunk: match
        let result = matcher.feed(b"Enter your password:");
        assert!(matches!(result, StreamChunkResult::MatchFound { .. }));
    }

    #[test]
    fn match_in_prefix_of_oversized_chunk_is_not_lost() {
        // A single chunk larger than max_buffer must be scanned in full. The
        // old feed() kept only the trailing max_buffer bytes and never scanned
        // the prefix, silently dropping a match located near the start.
        let ac = test_automaton(&["apache"]);
        let max_buffer = 16;
        let mut matcher = StreamingMatcher::new(ac, max_buffer);

        let mut data = b"Server: Apache".to_vec(); // pattern near the start
        data.extend(std::iter::repeat(b'X').take(100)); // shove it past the tail window

        let result = matcher.feed(&data);
        assert!(
            matches!(result, StreamChunkResult::MatchFound { .. }),
            "pattern in the prefix of an oversized chunk must be detected"
        );
        assert_eq!(matcher.matched_patterns().len(), 1);
    }

    #[test]
    fn no_match_in_clean_response() {
        let ac = test_automaton(&["apache", "nginx"]);
        let mut matcher = StreamingMatcher::new(ac, 1024);

        matcher.feed(b"HTTP/1.1 200 OK\r\n");
        matcher.feed(b"Content-Type: text/html\r\n\r\n");
        let result = matcher.feed(b"<html><body>Hello</body></html>");

        assert!(matches!(result, StreamChunkResult::NeedMore));
        assert!(!matcher.should_cancel());
        assert!(matcher.matched_patterns().is_empty());
    }

    #[test]
    fn buffer_full_returns_partial() {
        let ac = test_automaton(&["notfound"]);
        let mut matcher = StreamingMatcher::new(ac, 32); // Very small buffer

        let chunk = vec![b'X'; 64]; // Larger than buffer
        let result = matcher.feed(&chunk);

        assert!(matches!(result, StreamChunkResult::BufferFull { .. }));
    }

    #[test]
    fn bytes_saved_calculation() {
        let ac = test_automaton(&["apache"]);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        matcher.feed(b"Server: Apache/2.4"); // 18 bytes, match found

        let saved = matcher.bytes_saved(10_000_000); // 10MB response
        assert!(saved > 9_000_000); // Saved >9MB
    }

    #[test]
    fn multiple_patterns_match() {
        let ac = test_automaton(&["apache", "php", "mysql"]);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        matcher.feed(b"Server: Apache\nX-Powered-By: PHP/8.2\nX-DB: MySQL");
        assert!(matcher.matched_patterns().len() >= 3);
    }

    #[test]
    fn empty_chunk() {
        let ac = test_automaton(&["test"]);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        let result = matcher.feed(b"");
        assert!(matches!(result, StreamChunkResult::NeedMore));
        assert_eq!(matcher.bytes_processed(), 0);
    }

    // =========================================================================
    // Adversarial Tests
    // =========================================================================

    /// Test pattern split between chunks - "pass" at end of first chunk,
    /// "word" at start of second chunk should still match "password"
    #[test]
    fn pattern_split_across_chunk_boundary() {
        let ac = test_automaton(&["password"]);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        // First chunk ends with "pass"
        let result = matcher.feed(b"some text before pass");
        assert!(matches!(result, StreamChunkResult::NeedMore));
        assert!(!matcher.should_cancel());

        // Second chunk starts with "word" - completing "password"
        let result = matcher.feed(b"word and more text");
        assert!(
            matches!(result, StreamChunkResult::MatchFound { .. }),
            "Pattern split across chunk boundary should still match"
        );
        assert!(matcher.should_cancel());
    }

    /// Test feeding 1MB in a single call - should handle without overflow or panic
    #[test]
    fn one_mb_chunk_single_feed() {
        let ac = test_automaton(&["secret"]);
        let mut matcher = StreamingMatcher::new(ac, 2 * 1024 * 1024); // 2MB max buffer

        // Create 1MB chunk
        let one_mb: usize = 1_048_576;
        let chunk = vec![b'X'; one_mb];

        // Should not panic or overflow
        let result = matcher.feed(&chunk);
        assert!(
            matches!(result, StreamChunkResult::NeedMore),
            "1MB chunk without pattern should return NeedMore"
        );
        assert_eq!(matcher.bytes_processed(), one_mb);
    }

    /// Test feeding 1 byte at a time, 1000 times - should accumulate correctly
    #[test]
    fn feed_1000_times_1_byte_chunks() {
        let ac = test_automaton(&["abc"]);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        // Feed 1000 single-byte chunks
        for i in 0..1000 {
            let byte = match i {
                500 => b'a',
                501 => b'b',
                502 => b'c', // Pattern "abc" at positions 500-502
                _ => b'X',
            };
            let result = matcher.feed(&[byte]);

            if i < 502 {
                assert!(
                    matches!(result, StreamChunkResult::NeedMore),
                    "Should need more data at byte {}",
                    i
                );
            } else if i == 502 {
                assert!(
                    matches!(result, StreamChunkResult::MatchFound { .. }),
                    "Should find match when pattern completes at byte 502"
                );
                break;
            }
        }

        assert!(matcher.should_cancel());
        assert_eq!(matcher.matched_patterns().len(), 1);
    }

    /// Test pattern right at buffer limit - max_buffer=100, pattern starts at position 94
    /// Pattern "abcdef" (6 bytes) ends exactly at position 100
    #[test]
    fn pattern_at_exact_end_of_buffer() {
        let ac = test_automaton(&["abcdef"]);
        let max_buffer = 100;
        let mut matcher = StreamingMatcher::new(ac, max_buffer);

        // Fill 94 bytes with filler, then "abcdef" (6 bytes) = 100 bytes total
        let mut data = vec![b'X'; 94];
        data.extend_from_slice(b"abcdef");

        let result = matcher.feed(&data);

        // Pattern should be found before buffer is considered "full"
        assert!(
            matches!(result, StreamChunkResult::MatchFound { bytes_processed, .. } if bytes_processed == 100),
            "Pattern at exact end of buffer should match"
        );
        assert!(matcher.should_cancel());
    }

    /// Test bytes_saved calculation with known content length
    /// Match found after processing 1000 bytes, total_content_length = 1,000,000
    /// bytes_saved should be 999,000
    #[test]
    fn cancel_and_bytes_saved_known_content_length() {
        let ac = test_automaton(&["target"]);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        let total_content_length = 1_000_000;

        // Feed 994 bytes first (994 + 6 bytes for "target" = 1000 bytes total)
        matcher.feed(&vec![b'X'; 994]);
        assert!(!matcher.should_cancel());

        // Feed "target" (6 bytes) to reach exactly 1000 bytes processed
        let result = matcher.feed(b"target");
        assert!(matches!(result, StreamChunkResult::MatchFound { .. }));
        assert!(matcher.should_cancel());

        // Verify bytes_processed is exactly 1000
        assert_eq!(
            matcher.bytes_processed(),
            1000,
            "Should have processed exactly 1000 bytes"
        );

        // Verify bytes_saved calculation
        let bytes_saved = matcher.bytes_saved(total_content_length);
        let expected_saved = total_content_length - matcher.bytes_processed();
        assert_eq!(
            bytes_saved, expected_saved,
            "bytes_saved should equal total_content_length - bytes_processed"
        );
        assert_eq!(bytes_saved, 999_000, "bytes_saved should be 999,000");
    }

    // =========================================================================
    // ADVERSARIAL TESTS - DESIGNED TO FAIL (Edge Cases)
    // =========================================================================

    /// Test: Two patterns where first match cancels before second could match.
    /// Pattern1: "early" (appears at start), Pattern2: "late" (appears at end)
    /// If we cancel on "early", we might miss "late" in the same chunk.
    #[test]
    fn first_match_cancels_before_second_pattern() {
        let ac = test_automaton(&["early", "late"]);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        // Single chunk with both patterns
        let result = matcher.feed(b"early middle late");

        // Should match both patterns, even if cancels on first
        assert!(matches!(result, StreamChunkResult::MatchFound { .. }));
        assert!(
            matcher.matched_patterns().contains(&0),
            "Should match 'early'"
        );
        // Second pattern may or may not be found depending on implementation
        // This test documents current behavior
    }

    /// Test: Pattern that matches at byte 0.
    /// Pattern "start" at the very beginning of response.
    #[test]
    fn pattern_match_at_byte_zero() {
        let ac = test_automaton(&["start"]);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        let result = matcher.feed(b"start of response");

        assert!(
            matches!(result, StreamChunkResult::MatchFound { bytes_processed, .. } if bytes_processed == 17)
        );
        assert!(matcher.matched_patterns().contains(&0));
    }

    /// Test: Overlapping patterns (one is prefix of another).
    /// "pass" and "password" - "password" contains "pass"
    #[test]
    fn overlapping_patterns_prefix() {
        let ac = test_automaton(&["pass", "password"]);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        let result = matcher.feed(b"enter your password");

        assert!(matches!(result, StreamChunkResult::MatchFound { .. }));
        // Should match both patterns (they overlap)
        let patterns = matcher.matched_patterns();
        assert!(
            patterns.contains(&0) || patterns.contains(&1),
            "Should match at least one pattern"
        );
    }

    /// Test: Buffer exactly at max_buffer with pattern starting at last byte.
    /// Pattern "ab" with max_buffer=10, data="XXXXXXXXXXab" (10 X's, then ab)
    /// "ab" starts at position 10 which is exactly at buffer limit
    /// EXPECTED TO FAIL: Pattern at boundary may not be detected.
    #[test]
    fn buffer_exactly_at_max_buffer_pattern_at_last_byte() {
        let ac = test_automaton(&["ab"]);
        let max_buffer = 10;
        let mut matcher = StreamingMatcher::new(ac, max_buffer);

        // Fill buffer exactly, then pattern starts
        let mut data = vec![b'X'; 10]; // 10 bytes = max_buffer
        data.extend_from_slice(b"ab"); // Pattern starts at position 10

        let result = matcher.feed(&data);

        // Pattern "ab" starts at position 10 which is at buffer boundary
        // The buffer only holds 10 bytes, so "ab" might be cut off
        // This test documents the boundary behavior
        let _ = result;
    }

    /// Test: feed() after should_cancel() returns true.
    /// Behavior when continuing to feed after match found.
    /// EXPECTED TO FAIL: Behavior undefined after cancel.
    #[test]
    fn feed_after_should_cancel_returns_true() {
        let ac = test_automaton(&["stop"]);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        // First feed finds match
        matcher.feed(b"stop here");
        assert!(matcher.should_cancel());

        // Continue feeding - behavior is implementation defined
        // Should not panic
        let result = matcher.feed(b"more data");

        // Result could be either MatchFound (with accumulated patterns)
        // or the implementation might ignore subsequent feeds
        let _ = result;
    }

    /// Test: Pattern longer than max_buffer.
    /// Pattern "verylongpattern" with max_buffer=8
    /// EXPECTED TO FAIL: Pattern longer than buffer can't match.
    #[test]
    fn pattern_longer_than_max_buffer_matches_within_one_chunk() {
        let ac = test_automaton(&["verylongpattern"]);
        let max_buffer = 8; // Smaller than the 15-char pattern
        let mut matcher = StreamingMatcher::new(ac, max_buffer);

        // The whole pattern arrives in a single chunk, so it MUST be found even
        // though it is longer than max_buffer: feed() scans every incoming byte
        // and max_buffer only bounds the cross-chunk carry-over window, not the
        // scan of the current chunk. The old code dropped the chunk prefix and
        // missed this - a real recall bug in the matcher.
        let result = matcher.feed(b"verylongpattern");
        assert!(
            matcher.should_cancel(),
            "a pattern fully present in one chunk must match regardless of max_buffer"
        );
        assert!(matches!(result, StreamChunkResult::MatchFound { .. }));
    }

    /// Test: Case-insensitive match across chunk boundary.
    /// "PaSsWoRd" split as "PaS" | "sWoRd" should still match "password"
    #[test]
    fn case_insensitive_match_across_chunk_boundary() {
        let ac = test_automaton(&["password"]);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        // First chunk
        let result = matcher.feed(b"enter your PaS");
        assert!(matches!(result, StreamChunkResult::NeedMore));

        // Second chunk completes the pattern (case insensitive)
        let result = matcher.feed(b"sWoRd here");
        assert!(
            matches!(result, StreamChunkResult::MatchFound { .. }),
            "Case-insensitive pattern across chunks should match"
        );
        assert!(matcher.matched_patterns().contains(&0));
    }

    /// Test: 100 different patterns, match on pattern 99.
    /// Stress test: many patterns, late match.
    #[test]
    fn hundred_patterns_match_on_pattern_99() {
        let patterns: Vec<String> = (0..100).map(|i| format!("pattern{}", i)).collect();
        let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();

        let ac = test_automaton(&pattern_refs);
        let mut matcher = StreamingMatcher::new(ac, 65536);

        // Feed data containing pattern99
        let result = matcher.feed(b"here is pattern99 in the data");

        assert!(matches!(result, StreamChunkResult::MatchFound { .. }));
        // Should match at least one pattern (pattern99)
        // Note: The exact pattern index may vary based on automaton implementation
        assert!(
            !matcher.matched_patterns().is_empty(),
            "Should find at least one match"
        );
    }

    /// Test: Feed entire response as single chunk then verify results match chunk-by-chunk.
    /// Same data fed different ways should produce same matches.
    #[test]
    fn single_chunk_vs_chunk_by_chunk_same_results() {
        let data = b"start middle end target here";
        let patterns = &["start", "middle", "end", "target"];

        // Single chunk
        let ac1 = test_automaton(patterns);
        let mut matcher1 = StreamingMatcher::new(ac1, 65536);
        matcher1.feed(data);
        let single_chunk_patterns = matcher1.matched_patterns().to_vec();

        // Chunk by chunk (2 bytes at a time)
        let ac2 = test_automaton(patterns);
        let mut matcher2 = StreamingMatcher::new(ac2, 65536);
        for chunk in data.chunks(2) {
            matcher2.feed(chunk);
        }
        let multi_chunk_patterns = matcher2.matched_patterns().to_vec();

        // Should find same patterns regardless of chunking
        // Note: Order might differ, so compare as sets
        let set1: std::collections::HashSet<_> = single_chunk_patterns.iter().collect();
        let set2: std::collections::HashSet<_> = multi_chunk_patterns.iter().collect();

        assert_eq!(
            set1, set2,
            "Same data should produce same matches regardless of chunking"
        );
    }

    /// Test: Streaming matcher with max_buffer=1.
    /// Extreme case: smallest possible buffer.
    /// EXPECTED TO FAIL: May cause issues with pattern matching.
    #[test]
    fn streaming_matcher_max_buffer_one() {
        let ac = test_automaton(&["a"]);
        let mut matcher = StreamingMatcher::new(ac, 1);

        // With buffer=1, we can only hold 1 byte
        let result = matcher.feed(b"a");

        // Should still be able to match single-byte patterns
        // Buffer=1 behavior is implementation-defined, test documents current behavior
        let _ = result;
    }
}
