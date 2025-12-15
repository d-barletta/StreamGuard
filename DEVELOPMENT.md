# StreamGuard Development Setup

## Prerequisites

Install Rust via rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Project Structure

```bash
StreamGuard/
├── Cargo.toml              # Rust package manifest
├── src/
│   ├── lib.rs              # Library entry point
│   ├── core.rs             # Core types (Decision, Rule trait)
│   ├── engine.rs           # GuardEngine orchestrator
│   └── rules/
│       ├── mod.rs          # Rules module
│       └── sequence.rs     # ForbiddenSequenceRule implementation
├── tests/
│   └── integration_tests.rs # Integration tests
└── .github/
    └── copilot-instructions.md # AI agent development guide
```

## Building

```bash
cargo build
```

## Running Tests

```bash
cargo test
```

Run tests with output:

```bash
cargo test -- --nocapture
```

## Development Workflow

1. **Add a new rule**: Create a new file in `src/rules/`
2. **Implement the `Rule` trait**: See `sequence.rs` or `pattern.rs` for reference
3. **Add unit tests**: Test chunk boundaries and state management
4. **Add integration tests**: Test with `GuardEngine`

## Design Principles

See [.github/copilot-instructions.md](.github/copilot-instructions.md) for detailed development guidelines.

Key principles:

- Streaming-first (no buffering)
- Deterministic (same input → same output)
- O(n) processing
- Constant memory per rule
- No ML, no backtracking, no randomness

## DFA Implementation

The forbidden sequence rule uses the [aho-corasick](https://docs.rs/aho-corasick/) library for efficient
multi-pattern matching. This provides:

- **O(n + m) time complexity**: Linear in text length (n) and pattern length (m)
- **DFA-based matching**: True deterministic finite automaton implementation
- **Memory efficiency**: Compact state machine representation
- **Unicode support**: Handles international characters correctly
- **Streaming optimized**: Designed for incremental text processing

The aho-corasick algorithm is well-suited for security applications as it provides
predictable performance and deterministic behavior.

## Example Usage

```rust
use streamguard::{GuardEngine, rules::ForbiddenSequenceRule};

fn main() {
    let mut engine = GuardEngine::new();
    
    // Add a rule
    engine.add_rule(Box::new(ForbiddenSequenceRule::new(
        vec!["forbidden", "sequence"],
        "contains forbidden content",
    )));
    
    // Process stream
    let chunks = vec!["this is ", "forbidden ", "sequence"];
    
    for chunk in chunks {
        let decision = engine.feed(chunk);
        if decision.is_block() {
            println!("Blocked!");
            break;
        }
    }
}
```

## WASM Support

StreamGuard is `no_std` compatible and ready for WASM!

### Building for WASM

```bash
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release --no-default-features
```

### Using in no_std Environments

The crate can be used without the standard library:

```toml
[dependencies]
streamguard = { version = "0.1", default-features = false }
```

Note: In `no_std` environments, your application must provide:
- A global allocator (`#[global_allocator]`)
- A panic handler (`#[panic_handler]`)

The crate uses `alloc` for heap allocations (String, Vec, Box).

## Documentation

Generate and view documentation:

```bash
cargo doc --open
```

## License

Apache-2.0
