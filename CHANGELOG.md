# Changelog

## [0.2.0] - 2026-07-31

### Fixed
- Word matcher false negatives: identical patterns across templates or
  matchers shared one Aho-Corasick slot and only the first reported, and
  overlapping patterns (one a prefix of another) were suppressed by
  leftmost-first iteration. The automaton now runs an overlapping search
  over deduplicated pattern groups, so every matching template fires.
- Empty regex values were silently dropped at compile time; they now
  compile (the regex crate defines them as matching the empty string),
  while empty word/binary values are skipped with a loud warning.
- Streaming matcher rescanned the whole retained buffer per chunk
  (O(n^2) in chunk count, measured 98x for 10x chunks). It now rescans
  only the `max_pattern_len - 1` byte seam, and uses overlapping search
  so overlapping patterns are not under-reported.
- Streaming matcher returned NeedMore after a match had already fired;
  MatchFound is now a stable cumulative state.
- Truncating `as u16` casts for request/matcher/value indices wrapped at
  65536, misattributing matches; compile now fails closed with a
  validation error naming the template.
- `generate_java_gadget` emitted a truncated u16 length prefix for
  segments over 65535 bytes; over-long segments now return a DSL error.
- DSL parser rejected negative integer literals; `-5` now parses and
  folds to a literal, and unary minus on other operands lowers to
  `0 - operand`.
- DSL parser silently parsed out-of-range integer literals as 0;
  overflow now rejects the expression.
- DSL parser accepted chained comparisons (`a < b < c`); they now reject.
- Removed `expect()` panic paths in database compile (deny-level clippy)
  and two uses of `is_multiple_of` that violated the crate's 1.85 MSRV.
- Bench target failed to compile against current secir (`depends_on`).

### Added
- Regression tests for overlapping/duplicate word patterns, empty-regex
  semantics, streaming seam behavior, look-around rejection, parser
  negative literals and overflow, and gadget length limits.

## [0.1.0] - 2026-04-12

### Added
- Initial release of secmatch.
