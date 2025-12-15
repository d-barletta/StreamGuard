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

#![warn(missing_docs)]
#![warn(clippy::all)]

mod core;
mod engine;
pub mod rules;

// Re-export core types
pub use crate::core::{Decision, Rule, ScoredDecision};
pub use crate::engine::GuardEngine;
