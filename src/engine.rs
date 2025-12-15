//! The main GuardEngine that orchestrates rules and decisions

use crate::core::{Decision, Rule};

/// The main streaming guardrail engine
///
/// `GuardEngine` orchestrates multiple rules and processes text streams
/// incrementally. It maintains no global buffering - each chunk is
/// processed immediately and decisions are made in real-time.
///
/// # Example
///
/// ```rust
/// use streamguard::GuardEngine;
///
/// let mut engine = GuardEngine::new();
/// // Add rules: engine.add_rule(...)
///
/// // Process stream
/// let decision = engine.feed("chunk of text");
/// ```
pub struct GuardEngine {
    rules: Vec<Box<dyn Rule>>,
    stopped: bool,
}

impl GuardEngine {
    /// Create a new empty engine
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            stopped: false,
        }
    }

    /// Add a rule to the engine
    ///
    /// Rules are evaluated in the order they are added.
    /// The first rule to return a non-Allow decision wins.
    pub fn add_rule(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    /// Process a chunk of text through all rules
    ///
    /// # Arguments
    ///
    /// * `chunk` - The next piece of text to inspect
    ///
    /// # Returns
    ///
    /// A `Decision` indicating whether to allow, block, or rewrite
    ///
    /// # Behavior
    ///
    /// - If the engine has been stopped by a previous Block decision,
    ///   returns Block immediately without processing
    /// - Otherwise, feeds the chunk to each rule in order
    /// - Returns the first non-Allow decision
    /// - If all rules return Allow, returns Allow
    pub fn feed(&mut self, chunk: &str) -> Decision {
        // Once stopped, remain stopped
        if self.stopped {
            return Decision::Block {
                reason: "stream already blocked".to_string(),
            };
        }

        // Empty chunks are always allowed
        if chunk.is_empty() {
            return Decision::Allow;
        }

        // Evaluate rules in order
        for rule in &mut self.rules {
            let decision = rule.feed(chunk);

            match decision {
                Decision::Allow => continue,
                Decision::Block { .. } => {
                    self.stopped = true;
                    return decision;
                }
                Decision::Rewrite { .. } => {
                    return decision;
                }
            }
        }

        Decision::Allow
    }

    /// Reset the engine and all rules
    ///
    /// This clears the stopped state and resets all rule internal state.
    /// Use this when starting a new stream.
    pub fn reset(&mut self) {
        self.stopped = false;
        for rule in &mut self.rules {
            rule.reset();
        }
    }

    /// Check if the engine has been stopped
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Get the number of rules in the engine
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for GuardEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Simple test rule that blocks if it sees "bad"
    struct TestBlockRule {
        seen_bad: bool,
    }

    impl TestBlockRule {
        fn new() -> Self {
            Self { seen_bad: false }
        }
    }

    impl Rule for TestBlockRule {
        fn feed(&mut self, chunk: &str) -> Decision {
            if chunk.contains("bad") {
                self.seen_bad = true;
                Decision::Block {
                    reason: "found bad word".to_string(),
                }
            } else {
                Decision::Allow
            }
        }

        fn reset(&mut self) {
            self.seen_bad = false;
        }

        fn name(&self) -> &str {
            "test_block_rule"
        }
    }

    #[test]
    fn test_empty_engine_allows_all() {
        let mut engine = GuardEngine::new();
        assert_eq!(engine.feed("anything"), Decision::Allow);
        assert_eq!(engine.feed("more text"), Decision::Allow);
    }

    #[test]
    fn test_engine_blocks_on_rule_trigger() {
        let mut engine = GuardEngine::new();
        engine.add_rule(Box::new(TestBlockRule::new()));

        assert_eq!(engine.feed("good text"), Decision::Allow);
        assert!(!engine.is_stopped());

        let decision = engine.feed("bad text");
        assert!(decision.is_block());
        assert!(engine.is_stopped());
    }

    #[test]
    fn test_engine_stays_stopped_after_block() {
        let mut engine = GuardEngine::new();
        engine.add_rule(Box::new(TestBlockRule::new()));

        engine.feed("bad text");
        assert!(engine.is_stopped());

        // Further chunks should still be blocked
        let decision = engine.feed("more text");
        assert!(decision.is_block());
    }

    #[test]
    fn test_reset_clears_stopped_state() {
        let mut engine = GuardEngine::new();
        engine.add_rule(Box::new(TestBlockRule::new()));

        engine.feed("bad text");
        assert!(engine.is_stopped());

        engine.reset();
        assert!(!engine.is_stopped());

        // Should work again after reset
        assert_eq!(engine.feed("good text"), Decision::Allow);
    }

    #[test]
    fn test_empty_chunks_allowed() {
        let mut engine = GuardEngine::new();
        engine.add_rule(Box::new(TestBlockRule::new()));

        assert_eq!(engine.feed(""), Decision::Allow);
    }
}
