//! Streaming match engine  -  match as bytes arrive, cancel early on hit.
//!
//! Instead of downloading the complete response body and then running
//! Aho-Corasick, this module processes chunks as they arrive from the
//! network. If a match is found in the first 200 bytes of a 10MB
//! response, the remaining 9.99MB is never downloaded.
//!
//! For a scan with 10,000 templates against large responses, this
//! saves 90%+ of bandwidth.

use aho_corasick::AhoCorasick;

/// A streaming matcher that processes byte chunks incrementally.
pub struct StreamingMatcher {
    /// The Aho-Corasick automaton for word patterns.
    automaton: AhoCorasick,
    /// Accumulated bytes for partial matching.
    buffer: Vec<u8>,
    /// Maximum buffer size before we stop accumulating.
    max_buffer: usize,
    /// Pattern indices that have already matched.
    matched_patterns: Vec<usize>,
    /// Whether we've found enough matches to stop early.
    can_stop_early: bool,
    /// Total bytes processed.
    bytes_processed: usize,
    /// Trailing bytes rescanned with the next chunk (`max_pattern_len - 1`),
    /// the only region where a chunk-spanning match can start.
    seam: usize,
    /// Whether the automaton supports overlapping search (probed once).
    overlapping: bool,
}

/// Result of feeding a chunk to the streaming matcher.
#[derive(Debug)]
#[non_exhaustive]
pub enum StreamChunkResult {
    /// Need more data  -  no matches yet, keep streaming.
    NeedMore,
    /// Found matches  -  can optionally stop downloading.
    MatchFound {
        /// Indices of patterns that matched.
        pattern_indices: Vec<usize>,
        /// Bytes processed so far.
        bytes_processed: usize,
    },
    /// Buffer is full  -  process what we have.
    BufferFull {
        /// Indices of patterns that matched so far.
        pattern_indices: Vec<usize>,
        /// Bytes processed.
        bytes_processed: usize,
    },
}

mod matcher;

#[cfg(test)]
mod tests;
