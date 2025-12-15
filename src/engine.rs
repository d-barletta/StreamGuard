//! The main GuardEngine that orchestrates rules and decisions

use crate::core::{Decision, Rule};

/// Engine mode for handling rewrites
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewriteMode {
    /// First rewrite wins
    FirstWins,
    /// Chain all rewrites together
    Chain,
}

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
    score_threshold: Option<u32>,
    current_score: u32,
    score_decay: f32,
    rewrite_mode: RewriteMode,
    score_details: Vec<(String, u32)>,
}

impl GuardEngine {
    /// Create a new empty engine
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            stopped: false,
            score_threshold: None,
            current_score: 0,
            score_decay: 0.0,
            rewrite_mode: RewriteMode::FirstWins,
            score_details: Vec::new(),
        }
    }

    /// Create an engine with a score threshold
    pub fn with_score_threshold(threshold: u32) -> Self {
        Self {
            score_threshold: Some(threshold),
            ..Self::new()
        }
    }

    /// Create an engine with score decay
    pub fn with_score_decay(decay_rate: f32) -> Self {
        Self {
            score_decay: decay_rate.clamp(0.0, 1.0),
            ..Self::new()
        }
    }

    /// Create an engine with rewrite chaining enabled
    pub fn with_rewrite_chain() -> Self {
        Self {
            rewrite_mode: RewriteMode::Chain,
            ..Self::new()
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

        // Track scores and rewrites for this chunk
        let mut chunk_score = 0u32;
        let mut text = chunk.to_string();
        let mut has_rewrite = false;
        let mut first_block: Option<Decision> = None;
        self.score_details.clear();

        // Evaluate ALL rules to accumulate scores
        for rule in &mut self.rules {
            let decision = rule.feed(&text);
            let rule_score = rule.last_score();
            
            // Always accumulate scores from all rules
            if rule_score > 0 {
                chunk_score += rule_score;
                self.score_details.push((rule.name().to_string(), rule_score));
            }

            match decision {
                Decision::Allow => continue,
                Decision::Block { .. } => {
                    // In scoring mode (threshold or decay configured), don't stop on individual blocks
                    let scoring_mode = self.score_threshold.is_some() || self.score_decay > 0.0;
                    if !scoring_mode && first_block.is_none() {
                        first_block = Some(decision);
                    }
                }
                Decision::Rewrite { replacement } => {
                    if self.rewrite_mode == RewriteMode::Chain {
                        // Chain mode: apply rewrite and continue to next rule
                        text = replacement;
                        has_rewrite = true;
                    } else if first_block.is_none() {
                        // First-wins mode: remember first rewrite, but continue evaluating
                        first_block = Some(Decision::Rewrite { replacement });
                    }
                }
            }
        }

        // Update score after evaluating all rules
        self.current_score += chunk_score;

        // Apply score decay if configured (only if no new scores this chunk)
        if self.score_decay > 0.0 && chunk_score == 0 && self.current_score > 0 {
            self.current_score = (self.current_score as f32 * (1.0 - self.score_decay)) as u32;
        }

        // Check if score threshold is exceeded
        if let Some(threshold) = self.score_threshold {
            if self.current_score >= threshold {
                self.stopped = true;
                return Decision::Block {
                    reason: format!("score threshold exceeded: {} >= {}", self.current_score, threshold),
                };
            }
        }

        // Check if we had a blocking decision (only if no threshold, or threshold not the reason)
        if let Some(block_decision) = first_block {
            self.stopped = true;
            return block_decision;
        }

        // Check if score threshold is exceeded
        if let Some(threshold) = self.score_threshold {
            if self.current_score >= threshold {
                self.stopped = true;
                return Decision::Block {
                    reason: format!("score threshold exceeded: {} >= {}", self.current_score, threshold),
                };
            }
        }

        // Return chained rewrite if any rewrites occurred
        if has_rewrite {
            Decision::Rewrite { replacement: text }
        } else {
            Decision::Allow
        }
    }

    /// Reset the engine and all rules
    ///
    /// This clears the stopped state and resets all rule internal state.
    /// Use this when starting a new stream.
    pub fn reset(&mut self) {
        self.stopped = false;
        self.current_score = 0;
        self.score_details.clear();
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

    /// Get the current accumulated score
    pub fn current_score(&self) -> u32 {
        self.current_score
    }

    /// Get detailed score breakdown per rule
    pub fn score_details(&self) -> &[(String, u32)] {
        &self.score_details
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
