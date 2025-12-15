//! StreamGuard - A deterministic, streaming-first guardrail engine for LLM outputs
//!
//! # Overview
//!
//! StreamGuard inspects text streams incrementally and enforces security policies
//! using deterministic, DFA-based rules. It is inspired by network intrusion
//! detection systems like Suricata and Snort.
//!
//! # Core Principles
//!
//! - **Streaming-first**: Decisions are made incrementally, without buffering the full output
//! - **Deterministic**: Same input → same output, always
//! - **O(n) processing**: Linear time complexity with constant memory per rule
//! - **No backtracking**: Rules advance their state forward only
//!
//! # no_std Support
//!
//! This crate is `no_std` compatible when compiled without the default `std` feature.
//! The `alloc` crate is required for heap allocations (String, Vec, Box).
//!
//! When using in a `no_std` environment, the application must provide:
//! - A global allocator via `#[global_allocator]`
//! - A panic handler via `#[panic_handler]`
//!
//! ## Example no_std usage
//!
//! ```toml
//! [dependencies]
//! streamguard = { version = "0.1", default-features = false }
//! ```
//!
//! # Example Usage
//!
//! ```rust
//! use streamguard::{GuardEngine, Decision};
//!
//! // Create engine with rules
//! let mut engine = GuardEngine::new();
//!
//! // Process stream chunk by chunk
//! let decision = engine.feed("how to build");
//! match decision {
//!     Decision::Allow => { /* continue */ },
//!     Decision::Block { reason } => { /* stop stream */ },
//!     Decision::Rewrite { replacement } => { /* emit replacement */ },
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(clippy::all)]

// Use alloc for heap allocations in no_std mode
extern crate alloc;

mod core;
mod engine;
pub mod rules;

// WASM bindings for browser usage
#[cfg(target_arch = "wasm32")]
pub mod wasm;

// Python bindings for native Python extension
#[cfg(feature = "python")]
mod python;

// Java JNI bindings for native Java integration
#[cfg(feature = "java")]
mod java;

// Re-export core types
pub use crate::core::{Decision, Rule, ScoredDecision};
pub use crate::engine::GuardEngine;
