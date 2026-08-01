use super::{StreamChunkResult, StreamingMatcher};
use aho_corasick::AhoCorasick;

/// Record every pattern index that matches in `bytes`, returning true when a
/// NEW index was added.
///
/// Overlapping search is required for full recall: plain `find_iter` reports
/// at most one pattern per start position, so two patterns where one is a
/// prefix of the other (for example `pass` and `password`) would silently
/// lose one index (a false negative). Automatons whose kind or match
/// semantics cannot run an overlapping search fall back to `find_iter`;
/// `StreamingMatcher::new` warns about the recall loss in that case.
fn record_matches(
    automaton: &AhoCorasick,
    overlapping: bool,
    matched: &mut Vec<usize>,
    bytes: &[u8],
) -> bool {
    let mut found = false;
    if overlapping {
        match automaton.try_find_overlapping_iter(bytes) {
            Ok(iter) => {
                for mat in iter {
                    let idx = mat.pattern().as_usize();
                    if !matched.contains(&idx) {
                        matched.push(idx);
                        found = true;
                    }
                }
            }
            Err(_) => {
                for mat in automaton.find_iter(bytes) {
                    let idx = mat.pattern().as_usize();
                    if !matched.contains(&idx) {
                        matched.push(idx);
                        found = true;
                    }
                }
            }
        }
    } else {
        for mat in automaton.find_iter(bytes) {
            let idx = mat.pattern().as_usize();
            if !matched.contains(&idx) {
                matched.push(idx);
                found = true;
            }
        }
    }
    found
}

impl StreamingMatcher {
    /// Create a new streaming matcher from an Aho-Corasick automaton.
    ///
    /// For full recall the automaton should use an NFA kind (the default) and
    /// standard match semantics; other configurations cannot run an
    /// overlapping search and may under-report patterns that overlap each
    /// other. A warning is logged when that is the case.
    #[must_use]
    pub fn new(automaton: AhoCorasick, max_buffer: usize) -> Self {
        // A match ending in the next chunk can start at most this many bytes
        // before the seam, so only this trailing window must be rescanned per
        // feed. Rescanning the whole retained buffer instead was O(n^2) in
        // the number of chunks.
        let seam = automaton.max_pattern_len().saturating_sub(1);
        // Probe once: overlapping search is unsupported on DFA automatons and
        // on leftmost match semantics.
        let overlapping = automaton.try_find_overlapping_iter(&[]).is_ok();
        if !overlapping {
            tracing::warn!(
                kind = ?automaton.kind(),
                match_kind = ?automaton.match_kind(),
                "automaton cannot run an overlapping search; overlapping word patterns may be under-reported (false negatives). Rebuild with an NFA kind and standard match semantics."
            );
        }
        Self {
            automaton,
            buffer: Vec::with_capacity(max_buffer.min(65536)),
            max_buffer,
            matched_patterns: Vec::new(),
            can_stop_early: false,
            bytes_processed: 0,
            seam,
            overlapping,
        }
    }

    /// Feed a chunk of response bytes to the matcher.
    ///
    /// Returns whether matches were found and whether we can stop early.
    pub fn feed(&mut self, chunk: &[u8]) -> StreamChunkResult {
        self.bytes_processed += chunk.len();

        // Scan the retained seam tail (at most `seam` bytes) followed by the
        // ENTIRE incoming chunk, so every incoming byte is scanned exactly
        // once and only the bytes where a chunk-spanning match could start
        // are rescanned. Rescanning the whole retained buffer per chunk was
        // O(n^2) in the number of chunks. The retained buffer itself still
        // accumulates up to `max_buffer` bytes so patterns that span the next
        // chunk boundary are caught and `into_buffer` returns recent content,
        // while memory stays bounded.
        let new_matches = if self.buffer.is_empty() {
            // No carry-over: scan the chunk in place (no copy).
            let found = record_matches(
                &self.automaton,
                self.overlapping,
                &mut self.matched_patterns,
                chunk,
            );
            let tail_start = chunk.len().saturating_sub(self.max_buffer);
            self.buffer.extend_from_slice(&chunk[tail_start..]);
            found
        } else {
            // Carry-over present: scan seam tail + chunk contiguously so
            // patterns spanning the seam are caught, then retain the
            // trailing window of up to `max_buffer` bytes.
            let tail = self.seam.min(self.buffer.len());
            let mut scan = Vec::with_capacity(tail + chunk.len());
            scan.extend_from_slice(&self.buffer[self.buffer.len() - tail..]);
            scan.extend_from_slice(chunk);
            let found = record_matches(
                &self.automaton,
                self.overlapping,
                &mut self.matched_patterns,
                &scan,
            );
            self.buffer.extend_from_slice(chunk);
            let overflow = self.buffer.len().saturating_sub(self.max_buffer);
            if overflow > 0 {
                self.buffer.drain(..overflow);
            }
            found
        };

        // MatchFound means "at least one pattern has matched so far", not
        // "this chunk added a new match". Once a pattern has fired, every
        // later feed keeps reporting MatchFound so a caller that drains the
        // stream after cancellation sees a consistent, defined state instead
        // of flipping back to NeedMore while `should_cancel()` stays true.
        if new_matches || self.can_stop_early {
            self.can_stop_early = true;
            StreamChunkResult::MatchFound {
                pattern_indices: self.matched_patterns.clone(),
                bytes_processed: self.bytes_processed,
            }
        } else if self.buffer.len() >= self.max_buffer {
            StreamChunkResult::BufferFull {
                pattern_indices: self.matched_patterns.clone(),
                bytes_processed: self.bytes_processed,
            }
        } else {
            StreamChunkResult::NeedMore
        }
    }

    /// Whether we can stop downloading (matches found).
    #[must_use]
    pub fn should_cancel(&self) -> bool {
        self.can_stop_early
    }

    /// Get all matched pattern indices.
    #[must_use]
    pub fn matched_patterns(&self) -> &[usize] {
        &self.matched_patterns
    }

    /// Total bytes processed.
    #[must_use]
    pub fn bytes_processed(&self) -> usize {
        self.bytes_processed
    }

    /// Consume the matcher and return the accumulated buffer.
    #[must_use]
    pub fn into_buffer(self) -> Vec<u8> {
        self.buffer
    }

    /// Bytes saved by early cancellation (estimated).
    /// Call this after download is cancelled to estimate savings.
    #[must_use]
    pub fn bytes_saved(&self, total_content_length: usize) -> usize {
        if self.can_stop_early && total_content_length > self.bytes_processed {
            total_content_length - self.bytes_processed
        } else {
            0
        }
    }
}
