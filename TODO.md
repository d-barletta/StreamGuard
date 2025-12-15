# StreamGuard — Future Features & Roadmap

This document tracks planned features and improvements for StreamGuard.

All items must align with core principles: deterministic, streaming-first, O(n), constant memory.

---

## High Priority

### WASM Support

- [x] Make core engine `no_std`-friendly
- [x] Remove OS-specific API dependencies
- [x] Add WASM build target
- [ ] Create browser-based demo
- [ ] Benchmark WASM performance vs native

### Additional Rule Types

- [ ] Character-class constraints (e.g., max consecutive uppercase)
- [ ] Token frequency limits (e.g., "password" appears max 2x)
- [ ] JSON validity check

---

## Medium Priority

### Performance Optimizations

- [ ] SIMD optimizations for pattern matching
- [ ] Memory pool for state allocations
- [ ] Zero-copy chunk processing
- [ ] Profile and optimize hot paths

### Developer Experience

- [ ] Rule DSL or configuration format (JSON/YAML)
- [ ] CLI tool for testing rules
- [ ] Better error messages and diagnostics
- [ ] Rule debugging/tracing mode

### Documentation

- [ ] Comprehensive rule writing guide
- [ ] Performance tuning guide
- [ ] Architecture decision records (ADRs)
- [ ] Example integrations (web servers, CLI apps)

---

## Low Priority / Future Research

### Advanced Features

- [ ] Rule composition primitives (AND/OR/NOT)
- [ ] Conditional rules (if X matched, then apply Y)
- [ ] Stateful context tracking (e.g., conversation turn awareness)
- [ ] Streaming rewrite with lookahead buffer

### Ecosystem

- [ ] Python bindings
- [ ] JavaScript/TypeScript bindings (via WASM)
- [ ] Integration examples (LangChain, OpenAI SDK, etc.)
- [ ] Benchmark suite comparing to other guardrail solutions

### Tooling

- [ ] Fuzzer for rule engine
- [ ] Property-based testing framework
- [ ] Coverage-guided test generation

---

## Out of Scope (DO NOT IMPLEMENT)

These explicitly violate project principles:

- ❌ ML-based classifiers
- ❌ LLM-powered analysis
- ❌ Probabilistic matching
- ❌ Semantic embeddings
- ❌ Language detection via ML
- ❌ Sentiment analysis
- ❌ External API calls in core engine

---

## Notes

- Keep all features aligned with "untrusted stream" security model
- Maintain O(n) complexity guarantee
- No backtracking or buffering requirements
- Test coverage required before merging

---

Last updated: 2025-12-15
