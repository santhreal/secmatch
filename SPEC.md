# secmatch  -  Technical Spec

## Overview

Pure-computation pattern matching engine for Karyx.  This crate is the architectural crown jewel: zero I/O, zero network dependencies. It takes compiled templates and responses, produces matches and findings through Aho-Corasick + `RegexSet` fusion.  # Design invariants  - **No I/O.** This crate never touches the network or filesystem. - **No protocol knowledge.** It operates on `ResponseData`, not HTTP/DNS/TCP. - **Independently testable.** Every function is pure computation. - **Independently benchmarkable.** No mocks needed.

## Architecture

The crate is organized into the following public modules:

- `correlation`
- `database`
- `dsl`
- `evaluator`
- `extractor`
- `inter_template`
- `streaming`
- `text`

## Guarantees

- `#![forbid(unsafe_code)]` where applicable; see `src/lib.rs` for the exact lint preamble.
- All public types have doc comments.
- Error messages are actionable where applicable.

## Public API Summary

Key entry points are exported from `src/lib.rs` via `pub mod` and `pub use` re-exports.
Consult the module-level documentation in each source file for function signatures and usage examples.

## Error Handling

- Standard `Result` / error types.
