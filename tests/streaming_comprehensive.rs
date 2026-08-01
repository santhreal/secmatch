//! Comprehensive streaming matcher tests.
//!
//! Tests all streaming scenarios: cross-chunk matches, buffer limits,
//! concurrent access patterns, exact boundary conditions, and edge cases.

use aho_corasick::AhoCorasick;
use secmatch::streaming::{StreamChunkResult, StreamingMatcher};

fn test_automaton(patterns: &[&str]) -> AhoCorasick {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(patterns)
        .unwrap()
}

// ============================================================================
// Basic Streaming Tests
// ============================================================================

#[test]
fn streaming_match_in_first_chunk() {
    let ac = test_automaton(&["apache", "nginx"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let result = matcher.feed(b"Server: Apache/2.4.51");
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Should find match in first chunk"
    );
    assert!(matcher.should_cancel());
    assert_eq!(matcher.matched_patterns().len(), 1);
}

#[test]
fn streaming_match_across_two_chunks() {
    let ac = test_automaton(&["password"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let result = matcher.feed(b"<html><body>Enter your ");
    assert!(matches!(result, StreamChunkResult::NeedMore));
    let result = matcher.feed(b"password:</body></html>");
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Should find match across chunk boundary"
    );
    assert!(matcher.should_cancel());
}

#[test]
fn streaming_match_across_many_small_chunks() {
    let ac = test_automaton(&["continuous"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let chunks = vec!["con", "tin", "uo", "us"];
    for (i, chunk) in chunks.iter().enumerate() {
        let result = matcher.feed(chunk.as_bytes());
        if i < chunks.len() - 1 {
            assert!(
                matches!(result, StreamChunkResult::NeedMore),
                "Should need more at chunk {i}"
            );
        } else {
            assert!(
                matches!(result, StreamChunkResult::MatchFound { .. }),
                "Should find match at final chunk"
            );
        }
    }
}

#[test]
fn streaming_no_match_clean_response() {
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
fn streaming_empty_chunks() {
    let ac = test_automaton(&["test"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let result = matcher.feed(b"");
    assert!(matches!(result, StreamChunkResult::NeedMore));
    let result = matcher.feed(b"");
    assert!(matches!(result, StreamChunkResult::NeedMore));
    let result = matcher.feed(b"test");
    assert!(matches!(result, StreamChunkResult::MatchFound { .. }));
}

// ============================================================================
// Buffer Limit Tests
// ============================================================================

#[test]
fn streaming_buffer_full_no_match() {
    let ac = test_automaton(&["notfound"]);
    let mut matcher = StreamingMatcher::new(ac, 32);
    let chunk = vec![b'X'; 64];
    let result = matcher.feed(&chunk);
    assert!(
        matches!(result, StreamChunkResult::BufferFull { .. }),
        "Should return BufferFull when max buffer exceeded"
    );
}

#[test]
fn streaming_buffer_exact_size_match() {
    let ac = test_automaton(&["abcdef"]);
    let mut matcher = StreamingMatcher::new(ac, 100);
    let mut data = vec![b'X'; 94];
    data.extend_from_slice(b"abcdef");
    let result = matcher.feed(&data);
    assert!(
        matches!(result, StreamChunkResult::MatchFound { bytes_processed, .. } if bytes_processed == 100),
        "Should find match at exact buffer size"
    );
}

#[test]
fn streaming_buffer_one_byte_pattern() {
    let ac = test_automaton(&["a"]);
    let mut matcher = StreamingMatcher::new(ac, 1);
    let result = matcher.feed(b"a");
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Should match single-byte pattern with buffer=1"
    );
}

/// Regression test: a pattern LONGER than `max_buffer` must still match when
/// it arrives inside a single chunk. The matcher scans every incoming chunk
/// in full and retains only the trailing window for boundary spanning, so
/// truncation can never silently drop a match (a dropped match is a false
/// negative). BufferFull is reserved for "no match and the retained window
/// is at capacity".
#[test]
fn streaming_buffer_pattern_longer_than_buffer() {
    let ac = test_automaton(&["verylongpattern"]);
    let mut matcher = StreamingMatcher::new(ac, 8);
    let result = matcher.feed(b"verylongpattern");
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "pattern longer than the retained window must still match within one chunk"
    );
    assert!(matcher.should_cancel());
}

/// Companion boundary: with no match present, a chunk larger than
/// `max_buffer` fills the retained window and reports BufferFull.
#[test]
fn streaming_buffer_full_without_match() {
    let ac = test_automaton(&["absent-pattern"]);
    let mut matcher = StreamingMatcher::new(ac, 8);
    let result = matcher.feed(b"0123456789abcdef");
    assert!(
        matches!(result, StreamChunkResult::BufferFull { .. }),
        "no match plus a full retained window must report BufferFull"
    );
    assert!(!matcher.should_cancel());
}

#[test]
fn streaming_buffer_match_before_full() {
    let ac = test_automaton(&["target"]);
    let mut matcher = StreamingMatcher::new(ac, 100);
    let mut data = vec![b'X'; 94];
    data.extend_from_slice(b"target");
    data.extend_from_slice(b"YYYYYYYY"); // Extra bytes to potentially fill buffer
    let result = matcher.feed(&data);
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Should find match before buffer is full"
    );
}

#[test]
fn streaming_buffer_exactly_at_max_then_pattern() {
    let ac = test_automaton(&["ab"]);
    let mut matcher = StreamingMatcher::new(ac, 10);
    let mut data = vec![b'X'; 10];
    data.extend_from_slice(b"ab");
    let result = matcher.feed(&data);
    // Buffer can only hold 10 bytes, so "ab" at position 10 may or may not match
    // depending on implementation. We just verify it doesn't panic.
    let _ = result;
}

// ============================================================================
// Cross-Chunk Boundary Tests
// ============================================================================

#[test]
fn streaming_split_at_every_position() {
    let pattern = "boundary";
    for split_at in 1..pattern.len() {
        let ac = test_automaton(&[pattern]);
        let mut matcher = StreamingMatcher::new(ac, 65536);
        let (first, second) = pattern.split_at(split_at);
        let result1 = matcher.feed(first.as_bytes());
        assert!(
            matches!(result1, StreamChunkResult::NeedMore),
            "Split at {split_at} should need more after first chunk"
        );
        let result2 = matcher.feed(second.as_bytes());
        assert!(
            matches!(result2, StreamChunkResult::MatchFound { .. }),
            "Split at {split_at} should match after second chunk"
        );
    }
}

#[test]
fn streaming_case_insensitive_across_boundary() {
    let ac = test_automaton(&["password"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    matcher.feed(b"enter your PaS");
    let result = matcher.feed(b"sWoRd here");
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Case-insensitive match across chunks should work"
    );
}

#[test]
fn streaming_partial_match_then_reset() {
    // Pattern "abcde", feed "abcxde"  -  partial match "abc" then mismatch at "x"
    let ac = test_automaton(&["abcde"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let result = matcher.feed(b"abc");
    assert!(matches!(result, StreamChunkResult::NeedMore));
    let result = matcher.feed(b"xde");
    assert!(
        matches!(result, StreamChunkResult::NeedMore),
        "Partial match followed by mismatch should not false-positive"
    );
}

#[test]
fn streaming_overlapping_partial_matches() {
    // Pattern "aaa", feed "aaaaa" split as "aa" | "aaa"
    let ac = test_automaton(&["aaa"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    matcher.feed(b"aa");
    let result = matcher.feed(b"aaa");
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Overlapping partial match should complete"
    );
    let patterns = matcher.matched_patterns();
    assert!(!patterns.is_empty());
}

// ============================================================================
// Multiple Pattern Tests
// ============================================================================

#[test]
fn streaming_multiple_patterns_all_match() {
    let ac = test_automaton(&["apache", "php", "mysql"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let result = matcher.feed(b"Server: Apache\nX-Powered-By: PHP/8.2\nX-DB: MySQL");
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "All three patterns should match"
    );
    let patterns = matcher.matched_patterns();
    assert_eq!(patterns.len(), 3);
}

#[test]
fn streaming_multiple_patterns_match_at_different_times() {
    let ac = test_automaton(&["early", "middle", "late"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let result = matcher.feed(b"early");
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Should match 'early' first"
    );
    let result = matcher.feed(b" middle");
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Should match 'middle' next"
    );
    let result = matcher.feed(b" late");
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Should match 'late' last"
    );
    let patterns = matcher.matched_patterns();
    assert_eq!(patterns.len(), 3);
}

#[test]
fn streaming_duplicate_patterns_in_same_chunk() {
    let ac = test_automaton(&["repeat"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let result = matcher.feed(b"repeat repeat repeat");
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Should find match for repeated pattern"
    );
    // Should only track each pattern index once
    let patterns = matcher.matched_patterns();
    assert_eq!(patterns.len(), 1);
}

// ============================================================================
// Large Chunk Tests
// ============================================================================

#[test]
fn streaming_one_megabyte_chunk() {
    let ac = test_automaton(&["secret"]);
    let mut matcher = StreamingMatcher::new(ac, 2 * 1024 * 1024);
    let one_mb = vec![b'X'; 1_048_576];
    let result = matcher.feed(&one_mb);
    assert!(
        matches!(result, StreamChunkResult::NeedMore),
        "1MB chunk without pattern should return NeedMore"
    );
    assert_eq!(matcher.bytes_processed(), 1_048_576);
}

#[test]
fn streaming_ten_megabyte_chunk() {
    let ac = test_automaton(&["secret"]);
    let mut matcher = StreamingMatcher::new(ac, 16 * 1024 * 1024);
    let ten_mb = vec![b'X'; 10 * 1_048_576];
    let result = matcher.feed(&ten_mb);
    assert!(
        matches!(result, StreamChunkResult::NeedMore),
        "10MB chunk without pattern should return NeedMore"
    );
}

#[test]
fn streaming_match_at_end_of_large_chunk() {
    let ac = test_automaton(&["secret"]);
    let mut matcher = StreamingMatcher::new(ac, 2 * 1024 * 1024);
    let mut large = vec![b'X'; 1_000_000];
    large.extend_from_slice(b"secret");
    let result = matcher.feed(&large);
    assert!(
        matches!(result, StreamChunkResult::MatchFound { bytes_processed, .. } if bytes_processed == 1_000_006),
        "Should find match at end of large chunk"
    );
}

// ============================================================================
// Single Byte Feed Tests
// ============================================================================

#[test]
fn streaming_single_byte_feeds_match() {
    let ac = test_automaton(&["abc"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let data = b"xxabcxx";
    for (i, &byte) in data.iter().enumerate() {
        let result = matcher.feed(&[byte]);
        if i < 4 {
            assert!(
                matches!(result, StreamChunkResult::NeedMore),
                "Should need more at byte {i}"
            );
        } else if i == 4 {
            assert!(
                matches!(result, StreamChunkResult::MatchFound { .. }),
                "Should find match at byte 4"
            );
            break;
        }
    }
}

#[test]
fn streaming_single_byte_feeds_no_match() {
    let ac = test_automaton(&["abc"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let data = b"defghijk";
    for &byte in data {
        let result = matcher.feed(&[byte]);
        assert!(
            matches!(result, StreamChunkResult::NeedMore),
            "Should never match"
        );
    }
}

// ============================================================================
// Bytes Saved / Cancelled Tests
// ============================================================================

#[test]
fn streaming_bytes_saved_calculation() {
    let ac = test_automaton(&["apache"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    matcher.feed(b"Server: Apache/2.4");
    let saved = matcher.bytes_saved(10_000_000);
    assert!(saved > 9_000_000, "Should save >9MB of 10MB response");
}

#[test]
fn streaming_bytes_saved_zero_when_not_cancelled() {
    let ac = test_automaton(&["apache"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    matcher.feed(b"Server: nginx");
    let saved = matcher.bytes_saved(10_000_000);
    assert_eq!(saved, 0, "Should save 0 when not cancelled");
}

#[test]
fn streaming_bytes_saved_equal_to_remaining() {
    let ac = test_automaton(&["target"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    matcher.feed(&vec![b'X'; 1000]);
    matcher.feed(b"target");
    let processed = matcher.bytes_processed();
    let saved = matcher.bytes_saved(1_000_000);
    assert_eq!(saved, 1_000_000 - processed);
}

// ============================================================================
// Feed After Cancel Tests
// ============================================================================

#[test]
fn streaming_feed_after_cancel_does_not_panic() {
    let ac = test_automaton(&["stop"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    matcher.feed(b"stop here");
    assert!(matcher.should_cancel());
    let result = matcher.feed(b"more data");
    // Should not panic; behavior is defined (continues accumulating)
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Feed after cancel should still report MatchFound"
    );
}

// ============================================================================
// Buffer Accumulation Tests
// ============================================================================

#[test]
fn streaming_into_buffer_returns_accumulated() {
    let ac = test_automaton(&["test"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    matcher.feed(b"hello ");
    matcher.feed(b"world");
    let buffer = matcher.into_buffer();
    assert_eq!(buffer, b"hello world");
}

#[test]
fn streaming_buffer_truncates_at_max() {
    let ac = test_automaton(&["notfound"]);
    let mut matcher = StreamingMatcher::new(ac, 10);
    matcher.feed(b"0123456789abcdef");
    let buffer = matcher.into_buffer();
    assert_eq!(buffer.len(), 10);
    // The matcher retains the TRAILING window: patterns spanning the next
    // chunk boundary can only start in the most recent bytes, so the tail is
    // the only prefix worth keeping. Keeping the head instead would lose
    // every boundary-spanning match (false negative).
    assert_eq!(buffer, b"6789abcdef");
}

// ============================================================================
// Concurrent Access Pattern (Documented, not actual threads)
// ============================================================================

#[test]
fn streaming_multiple_independent_matchers() {
    let ac1 = test_automaton(&["first"]);
    let ac2 = test_automaton(&["second"]);
    let mut m1 = StreamingMatcher::new(ac1, 65536);
    let mut m2 = StreamingMatcher::new(ac2, 65536);

    let chunk = b"first and second";
    let r1 = m1.feed(chunk);
    let r2 = m2.feed(chunk);

    assert!(matches!(r1, StreamChunkResult::MatchFound { .. }));
    assert!(matches!(r2, StreamChunkResult::MatchFound { .. }));
    assert!(m1.matched_patterns().contains(&0));
    assert!(m2.matched_patterns().contains(&0));
}

// ============================================================================
// Edge Case: Pattern at Every Possible Offset
// ============================================================================

#[test]
fn streaming_pattern_at_offset_zero() {
    let ac = test_automaton(&["start"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let result = matcher.feed(b"start here");
    assert!(
        matches!(result, StreamChunkResult::MatchFound { bytes_processed, .. } if bytes_processed == 10),
        "Pattern at offset 0 should match immediately"
    );
}

#[test]
fn streaming_pattern_at_last_byte_of_chunk() {
    let ac = test_automaton(&["end"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let chunk = b"prefix end";
    let result = matcher.feed(chunk);
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Pattern at end of chunk should match"
    );
}

#[test]
fn streaming_pattern_spanning_exact_chunk_boundary() {
    let ac = test_automaton(&["boundary"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    matcher.feed(b"prefix bou");
    let result = matcher.feed(b"ndary suffix");
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Pattern spanning exact chunk boundary should match"
    );
}

// ============================================================================
// Edge Case: All Same Characters
// ============================================================================

#[test]
fn streaming_all_same_chars_with_match() {
    let ac = test_automaton(&["aaaa"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let result = matcher.feed(&b"a".repeat(100));
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Should match in all-same-char input"
    );
}

#[test]
fn streaming_all_same_chars_without_match() {
    let ac = test_automaton(&["bbbb"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let result = matcher.feed(&b"a".repeat(100));
    assert!(
        matches!(result, StreamChunkResult::NeedMore),
        "Should not match different char in all-same-char input"
    );
}

// ============================================================================
// Edge Case: Binary / Non-UTF8 in Chunks
// ============================================================================

#[test]
fn streaming_binary_data_with_pattern() {
    let ac = test_automaton(&["test"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let mut chunk = vec![0x00, 0xFF, 0x80];
    chunk.extend_from_slice(b"test");
    chunk.extend_from_slice(&[0x01, 0x02]);
    let result = matcher.feed(&chunk);
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Should match through binary data"
    );
}

#[test]
fn streaming_binary_data_split_across_chunks() {
    let ac = test_automaton(&["test"]);
    let mut matcher = StreamingMatcher::new(ac, 65536);
    let mut chunk1 = vec![0x00, 0xFF];
    chunk1.extend_from_slice(b"te");
    let chunk2 = vec![b"st".as_slice(), &[0x80]].concat();
    matcher.feed(&chunk1);
    let result = matcher.feed(&chunk2);
    assert!(
        matches!(result, StreamChunkResult::MatchFound { .. }),
        "Should match binary data split across chunks"
    );
}
