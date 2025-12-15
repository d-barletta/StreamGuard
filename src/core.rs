//! Core types and traits for StreamGuard

/// Decision returned by a rule or the engine
///
/// Decisions are final and immediate - they determine what happens
/// to the stream at this point in processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Allow the input to pass through unchanged
    Allow,

    /// Block the stream immediately and stop processing
    Block {
        /// Human-readable reason for blocking
        reason: String,
    },

    /// Rewrite the input with replacement text
    Rewrite {
        /// Text to emit instead of the original input
        replacement: String,
    },
}

impl Decision {
    /// Returns true if this decision allows the stream to continue
    #[inline]
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// Returns true if this decision blocks the stream
    #[inline]
    pub fn is_block(&self) -> bool {
        matches!(self, Decision::Block { .. })
    }

    /// Returns true if this decision rewrites the input
    #[inline]
    pub fn is_rewrite(&self) -> bool {
        matches!(self, Decision::Rewrite { .. })
    }
}

/// A streaming rule that inspects text incrementally
///
/// Rules must be:
/// - **Incremental**: Process input chunk-by-chunk
/// - **Stateful**: Maintain internal state across chunks
/// - **Cheap**: Evaluate efficiently without allocations
pub trait Rule: Send + Sync {
    /// Process a chunk of text and return a decision
    ///
    /// The chunk may be arbitrarily small (even a single character)
    /// or arbitrarily large. Rules must handle partial matches
    /// across chunk boundaries.
    ///
    /// # Arguments
    ///
    /// * `chunk` - The next piece of text to process
    ///
    /// # Returns
    ///
    /// A `Decision` that determines what happens to the stream
    fn feed(&mut self, chunk: &str) -> Decision;

    /// Reset the rule's internal state
    ///
    /// Called when starting a new stream or when the engine
    /// needs to reset processing.
    fn reset(&mut self);

    /// Optional: Get a human-readable name for this rule
    fn name(&self) -> &str {
        "unnamed_rule"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_predicates() {
        assert!(Decision::Allow.is_allow());
        assert!(!Decision::Allow.is_block());
        assert!(!Decision::Allow.is_rewrite());

        let block = Decision::Block {
            reason: "test".to_string(),
        };
        assert!(!block.is_allow());
        assert!(block.is_block());
        assert!(!block.is_rewrite());

        let rewrite = Decision::Rewrite {
            replacement: "test".to_string(),
        };
        assert!(!rewrite.is_allow());
        assert!(!rewrite.is_block());
        assert!(rewrite.is_rewrite());
    }
}
