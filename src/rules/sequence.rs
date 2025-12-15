//! Forbidden sequence detection using DFA-like state machines
//!
//! This rule detects forbidden token sequences in a streaming manner,
//! handling partial matches across chunk boundaries.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::core::{Decision, Rule};

/// Configuration for sequence matching behavior
#[derive(Debug, Clone)]
pub struct SequenceConfig {
    /// Whether to allow gaps (other words) between tokens
    /// - `true`: "how to not build" will match ["how", "to", "build"]
    /// - `false`: tokens must appear consecutively
    pub allow_gaps: bool,

    /// Words that break/reset the sequence when encountered
    /// Example: ["not", "never", "don't"] would reset on negations
    pub stop_words: Vec<String>,
}

impl Default for SequenceConfig {
    fn default() -> Self {
        Self {
            allow_gaps: true,
            stop_words: Vec::new(),
        }
    }
}

impl SequenceConfig {
    /// Create a new configuration with default settings (gaps allowed, no stop words)
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a strict configuration (no gaps, no stop words)
    pub fn strict() -> Self {
        Self {
            allow_gaps: false,
            stop_words: Vec::new(),
        }
    }

    /// Set whether gaps are allowed between tokens
    pub fn allow_gaps(mut self, allow: bool) -> Self {
        self.allow_gaps = allow;
        self
    }

    /// Add stop words that reset the sequence
    pub fn stop_words<S: AsRef<str>>(mut self, words: Vec<S>) -> Self {
        self.stop_words = words.iter().map(|s| s.as_ref().to_string()).collect();
        self
    }
}

/// A rule that blocks when a forbidden sequence of tokens is detected
///
/// This implementation uses a simple DFA-like state machine to detect
/// forbidden sequences while processing the stream incrementally.
///
/// # Behavior
///
/// - Tokens must appear **in order** but **may have gaps** between them (configurable)
/// - Example: `["how", "to", "hack"]` will match "how to safely hack" 
///   if `allow_gaps=true` (default)
/// - Stop words can be configured to reset the sequence detection
/// - For strict consecutive matching, use `SequenceConfig::strict()`
///
/// # Example
///
/// ```rust
/// use streamguard::rules::{ForbiddenSequenceRule, SequenceConfig};
/// use streamguard::Rule;
///
/// // Default: allows gaps
/// let mut rule = ForbiddenSequenceRule::new(
///     vec!["how", "to", "build", "bomb"],
///     "forbidden weapon instructions",
///     SequenceConfig::default()
/// );
///
/// // Strict: no gaps allowed
/// let mut strict_rule = ForbiddenSequenceRule::new(
///     vec!["password", "is"],
///     "credential leak",
///     SequenceConfig::strict()
/// );
///
/// // With stop words
/// let config = SequenceConfig::new()
///     .stop_words(vec!["not", "never", "don't"]);
/// let mut smart_rule = ForbiddenSequenceRule::new(
///     vec!["how", "to", "hack"],
///     "security threat",
///     config
/// );
/// ```
pub struct ForbiddenSequenceRule {
    /// The sequence of tokens to detect
    tokens: Vec<String>,
    /// Current position in the sequence (0-based)
    state: usize,
    /// Buffer for partial token matching across chunks
    buffer: String,
    /// Reason to return when blocking
    reason: String,
    /// Configuration for matching behavior
    config: SequenceConfig,
    /// Score to assign when matched
    score: u32,
    /// Replacement text for rewrites (None = block mode)
    replacement: Option<String>,
    /// Last score from the most recent decision
    last_decision_score: u32,
}

impl ForbiddenSequenceRule {
    /// Create a new forbidden sequence rule with configuration
    ///
    /// # Arguments
    ///
    /// * `tokens` - The sequence of tokens that trigger blocking
    /// * `reason` - Human-readable reason for blocking
    /// * `config` - Configuration for matching behavior
    pub fn new<S: AsRef<str>>(tokens: Vec<S>, reason: &str, config: SequenceConfig) -> Self {
        Self {
            tokens: tokens.iter().map(|s| s.as_ref().to_string()).collect(),
            state: 0,
            buffer: String::new(),
            reason: reason.to_string(),
            config,
            score: 0,
            replacement: None,
            last_decision_score: 0,
        }
    }

    /// Create a rule with default configuration (gaps allowed, no stop words)
    pub fn with_gaps<S: AsRef<str>>(tokens: Vec<S>, reason: &str) -> Self {
        Self::new(tokens, reason, SequenceConfig::default())
    }

    /// Create a strict rule (no gaps, no stop words)
    pub fn strict<S: AsRef<str>>(tokens: Vec<S>, reason: &str) -> Self {
        Self::new(tokens, reason, SequenceConfig::strict())
    }

    /// Create a rule with scoring
    pub fn new_with_score<S: AsRef<str>>(tokens: Vec<S>, reason: &str, score: u32) -> Self {
        Self {
            tokens: tokens.iter().map(|s| s.as_ref().to_string()).collect(),
            state: 0,
            buffer: String::new(),
            reason: reason.to_string(),
            config: SequenceConfig::default(),
            score,
            replacement: None,
            last_decision_score: 0,
        }
    }

    /// Create a rule with rewrite support
    pub fn new_with_rewrite<S: AsRef<str>>(tokens: Vec<S>, replacement: &str) -> Self {
        Self {
            tokens: tokens.iter().map(|s| s.as_ref().to_string()).collect(),
            state: 0,
            buffer: String::new(),
            reason: "rewrite forbidden sequence".to_string(),
            config: SequenceConfig::default(),
            score: 0,
            replacement: Some(replacement.to_string()),
            last_decision_score: 0,
        }
    }

    /// Check if buffer contains any stop word and reset if found
    fn check_stop_words(&mut self) -> bool {
        for stop_word in &self.config.stop_words {
            if self.buffer.contains(stop_word.as_str()) {
                // Found a stop word - reset the sequence
                self.state = 0;
                self.buffer.clear();
                return true;
            }
        }
        false
    }

    /// Check if the current buffer + new text matches the next token
    fn check_match(&mut self, chunk: &str) -> bool {
        // Append chunk to buffer
        self.buffer.push_str(chunk);

        // Check for stop words first
        if self.check_stop_words() {
            return false;
        }

        // For strict mode (no gaps), we need to ensure tokens are consecutive
        if !self.config.allow_gaps && self.state > 0 {
            // In strict mode, after finding a token, the next token must appear
            // immediately (only whitespace allowed between)
            let target = &self.tokens[self.state];
            let trimmed = self.buffer.trim_start();
            
            if trimmed.starts_with(target) {
                // Found next token immediately - advance
                self.state += 1;
                let after = target.len();
                self.buffer = trimmed[after..].to_string();
                
                if self.state >= self.tokens.len() {
                    return true;
                }
            } else if !trimmed.is_empty() && !trimmed.chars().all(char::is_whitespace) {
                // Non-whitespace content that doesn't match - reset
                self.state = 0;
                self.buffer.clear();
            }
            return false;
        }

        // Try to match tokens in sequence (with optional gaps)
        loop {
            if self.state >= self.tokens.len() {
                return true; // Matched entire sequence
            }

            let target = &self.tokens[self.state];

            // Check if buffer contains the target token
            if let Some(pos) = self.buffer.find(target) {
                // Found the token - advance state
                self.state += 1;

                // Clear buffer up to and including the matched token
                let after = pos + target.len();
                self.buffer = self.buffer[after..].to_string();

                // Check if we've matched the entire sequence
                if self.state >= self.tokens.len() {
                    return true;
                }
                // Continue loop to try matching next token immediately
            } else {
                // Token not found yet - need more input
                break;
            }
        }

        // Prevent buffer from growing unbounded
        // Keep only the last N characters where N is the longest token length
        let max_len = self.tokens.iter().map(|t| t.len()).max().unwrap_or(100);
        if self.buffer.len() > max_len * 2 {
            let keep = self.buffer.len() - max_len;
            self.buffer = self.buffer[keep..].to_string();
        }

        false
    }
}

impl Rule for ForbiddenSequenceRule {
    fn feed(&mut self, chunk: &str) -> Decision {
        if chunk.is_empty() {
            return Decision::Allow;
        }

        // Save original buffer content before check_match modifies it
        let original_buffer = self.buffer.clone();
        let original_chunk = chunk.to_string();
        
        if self.check_match(chunk) {
            // Match found - record score
            self.last_decision_score = self.score;
            
            // Reset state after match to avoid repeated matches
            self.state = 0;
            self.buffer.clear();
            
            // Check if this is a rewrite rule
            if let Some(ref replacement) = self.replacement {
                // For rewrite, work with the complete text (original buffer + chunk)
                let complete_text = format!("{}{}", original_buffer, original_chunk);
                let mut rewritten = complete_text.clone();
                
                // Replace each matched token with the replacement
                for token in &self.tokens {
                    rewritten = rewritten.replace(token, replacement);
                }
                
                Decision::Rewrite {
                    replacement: rewritten,
                }
            } else {
                // Block on match (engine will handle scoring vs blocking logic)
                Decision::Block {
                    reason: self.reason.clone(),
                }
            }
        } else {
            // No match - reset score
            self.last_decision_score = 0;
            Decision::Allow
        }
    }

    fn reset(&mut self) {
        self.state = 0;
        self.buffer.clear();
        self.last_decision_score = 0;
    }

    fn name(&self) -> &str {
        "forbidden_sequence"
    }

    fn last_score(&self) -> u32 {
        self.last_decision_score
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_sequence_in_one_chunk() {
        let mut rule = ForbiddenSequenceRule::with_gaps(
            vec!["how", "to", "build", "bomb"],
            "weapon instructions",
        );

        let decision = rule.feed("how to build bomb");
        assert!(decision.is_block());
    }

    #[test]
    fn test_sequence_across_chunks() {
        let mut rule = ForbiddenSequenceRule::with_gaps(
            vec!["how", "to", "build", "bomb"],
            "weapon instructions",
        );

        assert!(rule.feed("how ").is_allow());
        assert!(rule.feed("to bu").is_allow());
        assert!(rule.feed("ild a ").is_allow());
        assert!(rule.feed("bomb").is_block());
    }

    #[test]
    fn test_partial_match_then_diverge() {
        let mut rule = ForbiddenSequenceRule::with_gaps(
            vec!["how", "to", "build", "bomb"],
            "weapon instructions",
        );

        assert!(rule.feed("how ").is_allow());
        assert!(rule.feed("to cook").is_allow()); // Diverges
        assert!(rule.feed("dinner").is_allow());
    }

    #[test]
    fn test_reset_clears_state() {
        let mut rule = ForbiddenSequenceRule::with_gaps(
            vec!["how", "to", "build", "bomb"],
            "weapon instructions",
        );

        rule.feed("how to build");
        rule.reset();

        // After reset, partial sequence doesn't continue
        assert!(rule.feed("bomb").is_allow());
    }

    #[test]
    fn test_empty_chunk_allows() {
        let mut rule = ForbiddenSequenceRule::with_gaps(vec!["bad"], "test");
        assert!(rule.feed("").is_allow());
    }

    #[test]
    fn test_non_matching_text() {
        let mut rule = ForbiddenSequenceRule::with_gaps(
            vec!["forbidden", "sequence"],
            "test",
        );

        assert!(rule.feed("this is normal text").is_allow());
        assert!(rule.feed("with no issues").is_allow());
    }

    #[test]
    fn test_single_token_sequence() {
        let mut rule = ForbiddenSequenceRule::with_gaps(vec!["forbidden"], "single token");

        assert!(rule.feed("this is ").is_allow());
        assert!(rule.feed("forbidden").is_block());
    }

    // New tests for strict mode (no gaps)
    #[test]
    fn test_strict_mode_consecutive_tokens() {
        let mut rule = ForbiddenSequenceRule::strict(
            vec!["password", "is"],
            "credential leak",
        );

        assert!(rule.feed("password ").is_allow());
        assert!(rule.feed("is").is_block());
    }

    #[test]
    fn test_strict_mode_rejects_gaps() {
        let mut rule = ForbiddenSequenceRule::strict(
            vec!["secret", "key"],
            "data leak",
        );

        assert!(rule.feed("secret ").is_allow());
        assert!(rule.feed("encryption key").is_allow()); // Gap breaks sequence
    }

    #[test]
    fn test_stop_words_reset_sequence() {
        let config = SequenceConfig::new().stop_words(vec!["not", "never"]);
        let mut rule = ForbiddenSequenceRule::new(
            vec!["how", "to", "hack"],
            "security threat",
            config,
        );

        assert!(rule.feed("how ").is_allow());
        assert!(rule.feed("to not ").is_allow()); // "not" resets
        assert!(rule.feed("hack").is_allow()); // No longer in sequence
    }

    #[test]
    fn test_stop_words_in_single_chunk() {
        let config = SequenceConfig::new().stop_words(vec!["not"]);
        let mut rule = ForbiddenSequenceRule::new(
            vec!["how", "to", "build", "bomb"],
            "weapon instructions",
            config,
        );

        assert!(rule.feed("how to not build a bomb").is_allow());
    }

    #[test]
    fn test_multiple_stop_words() {
        let config = SequenceConfig::new().stop_words(vec!["not", "never", "don't"]);
        let mut rule = ForbiddenSequenceRule::new(
            vec!["steal", "password"],
            "security",
            config,
        );

        assert!(rule.feed("don't steal ").is_allow()); // Resets
        assert!(rule.feed("password").is_allow());
    }
}
