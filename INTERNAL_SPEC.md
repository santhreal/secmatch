# secmatch  -  Internal Spec

> This file is gitignored. It exists for agents and internal development. Never committed to public repos.

## Identity
High-performance scan executor for `secir` templates.

## Purpose
Consumes `secir` templates and executes them against targets over various protocols (HTTP, DNS, TCP, etc.), producing `secfinding` instances as results.

## North Star
The fastest and most efficient scan execution engine, capable of running thousands of multi-step templates per second with minimal resource footprint.

## Role in Ecosystem
- **Depends on:** `secir`, `secfinding`, `scanclient`.
- **Depended on by:** `warpscan`, `scancoord`, and other high-level scan orchestration tools.
- **Relationship to warpscan:** The primary execution engine for all scanner modules.
- **Standalone value:** YES  -  A modular and performant engine for executing security scan templates.

## Invariants
- Matchers must never produce false positives if all conditions are met correctly.
- Multi-step flows (iterate, conditional requests) are executed with strict state isolation.
- Rate limiting and target management are consistently applied across all probes.

## Boundaries
- Does not define the scan template format (uses `secir`).
- Does not handle template distribution or target discovery (managed by orchestration layers).

## Quality State
- Tests: >10 including property and adversarial tests.
- Lint preamble: yes (pedantic)
- #![forbid(unsafe_code)]: yes
- Doc coverage: ~85%
- Known issues: None.
