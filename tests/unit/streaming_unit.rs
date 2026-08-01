use aho_corasick::AhoCorasick;
use secmatch::streaming::{StreamChunkResult, StreamingMatcher};

fn create_matcher(patterns: &[&str], max_buffer: usize) -> StreamingMatcher {
    let ac = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(patterns)
        .unwrap();
    StreamingMatcher::new(ac, max_buffer)
}

#[test]
fn test_streaming_matcher_empty_buffer() {
    let mut matcher = create_matcher(&["test"], 1024);
    let result = matcher.feed(b"");
    assert!(matches!(result, StreamChunkResult::NeedMore));
    assert!(!matcher.should_cancel());
}

#[test]
fn test_streaming_matcher_exact_chunk_boundary() {
    let mut matcher = create_matcher(&["boundary"], 1024);
    let _ = matcher.feed(b"this is a boun");
    let result = matcher.feed(b"dary condition");

    if let StreamChunkResult::MatchFound {
        pattern_indices, ..
    } = result
    {
        assert_eq!(pattern_indices.len(), 1);
        assert_eq!(pattern_indices[0], 0);
    } else {
        panic!("Expected MatchFound");
    }
}

/// Regression test: a pattern spanning two chunks must match even when it is
/// longer than `max_buffer`. The matcher rescans the `max_pattern_len - 1`
/// byte seam with each chunk precisely so this boundary case cannot become a
/// false negative; `max_buffer` only bounds the retained accumulation window.
#[test]
fn test_streaming_matcher_max_buffer_exceeded() {
    let mut matcher = create_matcher(&["pattern"], 5);
    let result1 = matcher.feed(b"pat");
    assert!(matches!(result1, StreamChunkResult::NeedMore));

    let result2 = matcher.feed(b"tern");
    assert!(
        matches!(result2, StreamChunkResult::MatchFound { .. }),
        "pattern spanning the chunk seam must match despite tiny max_buffer"
    );
    assert!(matcher.should_cancel());
    // The retained window never exceeds max_buffer.
    assert!(matcher.into_buffer().len() <= 5);
}
