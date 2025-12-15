# StreamGuard — Developer Instructions for GitHub Copilot

## Project Context (READ FIRST)

You are assisting in the development of **StreamGuard**, an open-source Rust project.

StreamGuard is a **deterministic, streaming-first guardrail engine for LLM outputs**, inspired by network intrusion detection systems (IDS) like Suricata and Snort.

The project goal is:
- inspect text streams incrementally
- apply deterministic rules (DFA-based)
- make immediate decisions (allow / block / rewrite)
- work without LLMs or probabilistic models
- be suitable for backend, edge, and WASM

This is a **systems/security project**, not an NLP or ML project.

---

## Core Design Principles (DO NOT VIOLATE)

- Streaming-first: never require the full output to be buffered
- Deterministic behavior: same input → same output
- O(n) processing
- Constant memory per rule
- No backtracking
- No retries
- No randomness
- No ML models
- No external API calls in the core engine

---

## Architecture Overview

The system consists of:

- GuardEngine: orchestrates rules and decisions
- Rule: a stateful streaming matcher (DFA)
- GuardState: global state across the stream
- Decision: allow / block / rewrite

Each rule maintains its own internal state.

---

## Core Types (Conceptual)

```rust
enum Decision {
    Allow,
    Block { reason: String },
    Rewrite { replacement: String },
}

trait Rule {
    fn feed(&mut self, chunk: &str) -> Decision;
    fn reset(&mut self);
}
```

Rules must be:

* incremental
* stateful
* cheap to evaluate

---

## Implementation Guidelines

* Prefer explicit state machines over clever abstractions
* Avoid async in the core engine unless strictly necessary
* No heap allocations in the hot path
* Use slices and references where possible
* Favor clarity over cleverness
* Code must be auditable and easy to reason about

---

## DFA Rules

* Implement forbidden sequences using DFA-like state machines
* Support partial matches across chunks
* Support optional gaps between tokens
* Do NOT implement semantic analysis
* Matching is lexical, not contextual

---

## Streaming Behavior

* The engine processes input chunk-by-chunk
* Decisions are final once returned
* On `Block`, the stream must stop immediately
* On `Rewrite`, replacement text is emitted inline
* On `Allow`, input passes through unchanged

---

## Testing Expectations

* All rules must have deterministic unit tests
* Tests must cover:

  * chunk boundaries
  * partial matches
  * reset behavior
  * false positives
* No snapshot tests
* No golden text comparisons

---

## What NOT to Implement

* No NLP libraries
* No language detection
* No sentiment analysis
* No embedding-based similarity
* No calling other LLMs
* No probabilistic classifiers

---

## Performance Targets

* Linear time complexity
* Predictable memory usage
* Suitable for long or infinite streams

---

## Rust Style

* Follow idiomatic Rust
* Avoid unsafe unless absolutely required (and document it)
* Use enums and pattern matching for state
* Prefer small modules with clear responsibility

---

## WASM Considerations (Future)

* Avoid OS-specific APIs
* Avoid threading assumptions
* Keep core logic `no_std`-friendly where possible

---

## Commit Discipline

* Small, focused commits
* Each commit should compile and pass tests
* Prefer descriptive commit messages

---

## Copilot Usage Instructions

When generating code:

* Do NOT introduce new concepts unless explicitly requested
* Follow the existing architecture
* Ask for clarification via comments if something is ambiguous
* Generate minimal code first, then extend

When in doubt:

* Default to simpler, more explicit logic

---

## Project Philosophy

Treat LLM output as an **untrusted stream**.

This project applies **systems and security engineering principles** to AI output enforcement.

---

## End of Instructions
