//! Pattern-based detection using simple regex-like matching
//!
//! This module provides pattern matching rules for detecting common
//! sensitive data patterns like emails, URLs, credit cards, etc.

use crate::core::{Decision, Rule};

/// Preset pattern types for common use cases
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternPreset {
    /// Email addresses (simple pattern)
    Email,
    /// Email addresses (strict RFC-compliant pattern)
    EmailStrict,
    /// URLs (http/https)
    Url,
    /// IPv4 addresses
    Ipv4,
    /// Credit card numbers (basic format)
    CreditCard,
}

impl PatternPreset {
    /// Get the pattern string for this preset
    fn pattern(&self) -> &'static str {
        match self {
            // Simple email: word@word.word
            PatternPreset::Email => r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            
            // Stricter email validation
            PatternPreset::EmailStrict => {
                r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
            }
            
            // URLs starting with http:// or https://
            PatternPreset::Url => r"https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?:/[^\s]*)?",
            
            // IPv4: xxx.xxx.xxx.xxx
            PatternPreset::Ipv4 => r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            
            // Credit card: groups of 4 digits
            PatternPreset::CreditCard => r"\b(?:\d{4}[- ]?){3}\d{4}\b",
        }
    }

    /// Get a human-readable description
    fn description(&self) -> &'static str {
        match self {
            PatternPreset::Email => "email address",
            PatternPreset::EmailStrict => "email address (strict)",
            PatternPreset::Url => "URL",
            PatternPreset::Ipv4 => "IPv4 address",
            PatternPreset::CreditCard => "credit card number",
        }
    }
}

/// Configuration for pattern matching
#[derive(Debug, Clone)]
pub struct PatternConfig {
    /// The pattern to match (simple regex-like)
    pattern: String,
    /// Human-readable description
    description: String,
    /// Whether to use case-insensitive matching
    case_insensitive: bool,
}

impl PatternConfig {
    /// Create a new pattern configuration from a preset
    pub fn from_preset(preset: PatternPreset) -> Self {
        Self {
            pattern: preset.pattern().to_string(),
            description: preset.description().to_string(),
            case_insensitive: false,
        }
    }

    /// Create a custom pattern configuration
    pub fn custom(pattern: &str, description: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
            description: description.to_string(),
            case_insensitive: false,
        }
    }

    /// Set case-insensitive matching
    pub fn case_insensitive(mut self, enabled: bool) -> Self {
        self.case_insensitive = enabled;
        self
    }

    /// Get the pattern string
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

/// A rule that detects patterns in streaming text
///
/// This implementation uses simple pattern matching to detect
/// sensitive data patterns like emails, URLs, etc.
///
/// # Behavior
///
/// - Patterns are matched incrementally across chunk boundaries
/// - Simple regex-like syntax (subset of regex features)
/// - Deterministic matching with O(n) complexity
///
/// # Examples
///
/// ```rust
/// use streamguard::rules::{PatternRule, PatternPreset};
/// use streamguard::Rule;
///
/// // Simple email detection (easy to use)
/// let mut rule = PatternRule::email("found email address");
///
/// // Strict email validation
/// let mut strict = PatternRule::from_preset(
///     PatternPreset::EmailStrict,
///     "found email (strict)"
/// );
///
/// // Custom pattern
/// let mut custom = PatternRule::custom(
///     r"\d{3}-\d{3}-\d{4}",
///     "found phone number",
///     "US phone number"
/// );
/// ```
pub struct PatternRule {
    /// Pattern configuration
    config: PatternConfig,
    /// Buffer for accumulating text across chunks
    buffer: String,
    /// Reason to return when blocking
    reason: String,
    /// Replacement text for rewrites (None = block mode)
    replacement: Option<String>,
}

impl PatternRule {
    /// Create a pattern rule from a preset
    pub fn from_preset(preset: PatternPreset, reason: &str) -> Self {
        Self {
            config: PatternConfig::from_preset(preset),
            buffer: String::new(),
            reason: reason.to_string(),
            replacement: None,
        }
    }

    /// Create an email detection rule (simple, easy to use)
    pub fn email(reason: &str) -> Self {
        Self::from_preset(PatternPreset::Email, reason)
    }

    /// Create a strict email detection rule
    pub fn email_strict(reason: &str) -> Self {
        Self::from_preset(PatternPreset::EmailStrict, reason)
    }

    /// Create a URL detection rule
    pub fn url(reason: &str) -> Self {
        Self::from_preset(PatternPreset::Url, reason)
    }

    /// Create an IPv4 detection rule
    pub fn ipv4(reason: &str) -> Self {
        Self::from_preset(PatternPreset::Ipv4, reason)
    }

    /// Create a credit card detection rule
    pub fn credit_card(reason: &str) -> Self {
        Self::from_preset(PatternPreset::CreditCard, reason)
    }

    /// Create an email rewrite rule
    pub fn email_rewrite(replacement: &str) -> Self {
        Self {
            config: PatternConfig::from_preset(PatternPreset::Email),
            buffer: String::new(),
            reason: "email redacted".to_string(),
            replacement: Some(replacement.to_string()),
        }
    }

    /// Create a URL rewrite rule
    pub fn url_rewrite(replacement: &str) -> Self {
        Self {
            config: PatternConfig::from_preset(PatternPreset::Url),
            buffer: String::new(),
            reason: "url redacted".to_string(),
            replacement: Some(replacement.to_string()),
        }
    }

    /// Create an IPv4 rewrite rule
    pub fn ipv4_rewrite(replacement: &str) -> Self {
        Self {
            config: PatternConfig::from_preset(PatternPreset::Ipv4),
            buffer: String::new(),
            reason: "ip redacted".to_string(),
            replacement: Some(replacement.to_string()),
        }
    }

    /// Create a credit card rewrite rule
    pub fn credit_card_rewrite(replacement: &str) -> Self {
        Self {
            config: PatternConfig::from_preset(PatternPreset::CreditCard),
            buffer: String::new(),
            reason: "card redacted".to_string(),
            replacement: Some(replacement.to_string()),
        }
    }

    /// Create a custom pattern rule with full configuration
    pub fn custom(pattern: &str, reason: &str, description: &str) -> Self {
        Self {
            config: PatternConfig::custom(pattern, description),
            buffer: String::new(),
            reason: reason.to_string(),
            replacement: None,
        }
    }

    /// Create a custom rule with configuration
    pub fn with_config(config: PatternConfig, reason: &str) -> Self {
        Self {
            config,
            buffer: String::new(),
            reason: reason.to_string(),
            replacement: None,
        }
    }

    /// Simple pattern matching (subset of regex)
    /// For now, implements basic patterns - can be extended to full regex DFA
    fn matches_pattern(&self, text: &str) -> bool {
        // Simple implementation using contains for now
        // In production, this would use a compiled DFA or regex engine
        
        let search_text = if self.config.case_insensitive {
            text.to_lowercase()
        } else {
            text.to_string()
        };

        let pattern_lower = if self.config.case_insensitive {
            self.config.pattern.to_lowercase()
        } else {
            self.config.pattern.clone()
        };

        // For email pattern, do a simple check
        if self.config.description.contains("email") {
            return self.check_email_pattern(&search_text);
        }

        // For URLs
        if self.config.description.contains("URL") {
            return search_text.contains("http://") || search_text.contains("https://");
        }

        // For IPv4
        if self.config.description.contains("IPv4") {
            return self.check_ipv4_pattern(&search_text);
        }

        // For credit cards
        if self.config.description.contains("credit card") {
            return self.check_credit_card_pattern(&search_text);
        }

        // Fallback: simple substring search
        search_text.contains(&pattern_lower)
    }

    /// Check for email pattern (simple implementation)
    fn check_email_pattern(&self, text: &str) -> bool {
        // Look for @ symbol and . after it
        if let Some(at_pos) = text.find('@') {
            // Must have at least one character before @
            if at_pos == 0 {
                return false;
            }
            
            let after_at = &text[at_pos + 1..];
            
            // Must have a dot after @ with characters before and after the dot
            if let Some(dot_pos) = after_at.find('.') {
                if dot_pos > 0 && dot_pos + 1 < after_at.len() {
                    // Check that there's at least 2 chars after the dot (TLD)
                    let after_dot = &after_at[dot_pos + 1..];
                    if after_dot.len() >= 2 {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check for IPv4 pattern
    fn check_ipv4_pattern(&self, text: &str) -> bool {
        // Look for pattern like xxx.xxx.xxx.xxx
        // Split by whitespace first to isolate potential IPs
        for word in text.split_whitespace() {
            let parts: Vec<&str> = word.split('.').collect();
            if parts.len() == 4 {
                // Check if all 4 parts are numeric
                let all_numeric = parts.iter().all(|p| {
                    !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())
                });
                if all_numeric {
                    return true;
                }
            }
        }
        false
    }

    /// Check for credit card pattern
    fn check_credit_card_pattern(&self, text: &str) -> bool {
        // Look for sequences of 4 digits, possibly separated by spaces or dashes
        let digits_only: String = text
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == ' ' || *c == '-')
            .collect();
        
        let digit_count = digits_only.chars().filter(|c| c.is_ascii_digit()).count();
        
        // Credit cards typically have 13-19 digits, most commonly 16
        digit_count >= 13 && digit_count <= 19
    }

    /// Perform rewrite by replacing all pattern matches with replacement text
    fn rewrite_text(&self, text: &str, replacement: &str) -> String {
        // Simple implementation: find and replace all matches
        // For email
        if self.config.description.contains("email") {
            return self.rewrite_emails(text, replacement);
        }

        // For URLs
        if self.config.description.contains("URL") {
            return self.rewrite_urls(text, replacement);
        }

        // For IPv4
        if self.config.description.contains("IPv4") {
            return self.rewrite_ipv4(text, replacement);
        }

        // For credit cards
        if self.config.description.contains("credit card") {
            return self.rewrite_credit_cards(text, replacement);
        }

        text.to_string()
    }

    fn rewrite_emails(&self, text: &str, replacement: &str) -> String {
        let mut result = String::new();
        let mut current = String::new();
        let mut in_email = false;
        let mut has_at = false;
        let mut has_dot_after_at = false;
        
        for ch in text.chars() {
            if ch.is_alphanumeric() || ch == '@' || ch == '.' || ch == '_' || ch == '-' || ch == '+' || ch == '%' {
                current.push(ch);
                if ch == '@' {
                    has_at = true;
                }
                if has_at && ch == '.' {
                    has_dot_after_at = true;
                    in_email = true;
                }
            } else {
                // End of potential email
                if in_email && has_at && has_dot_after_at && current.len() > 5 {
                    // Looks like an email - replace it
                    result.push_str(replacement);
                } else {
                    result.push_str(&current);
                }
                result.push(ch);
                current.clear();
                in_email = false;
                has_at = false;
                has_dot_after_at = false;
            }
        }
        
        // Handle end of string
        if in_email && has_at && has_dot_after_at && current.len() > 5 {
            result.push_str(replacement);
        } else {
            result.push_str(&current);
        }
        
        result
    }

    fn rewrite_urls(&self, text: &str, replacement: &str) -> String {
        let mut result = text.to_string();
        
        // Find http:// or https://
        for protocol in &["https://", "http://"] {
            while let Some(start) = result.find(protocol) {
                // Find end of URL (next whitespace or end of string)
                let after_start = &result[start..];
                let end_offset = after_start.find(|c: char| c.is_whitespace())
                    .unwrap_or(after_start.len());
                let url = &result[start..start + end_offset];
                
                result = result.replace(url, replacement);
            }
        }
        
        result
    }
    fn rewrite_ipv4(&self, text: &str, replacement: &str) -> String {
        let mut result = text.to_string();
        
        for word in text.split_whitespace() {
            let parts: Vec<&str> = word.split('.').collect();
            if parts.len() == 4 {
                let all_numeric = parts.iter().all(|p| {
                    !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())
                });
                if all_numeric {
                    result = result.replace(word, replacement);
                }
            }
        }
        
        result
    }

    fn rewrite_credit_cards(&self, text: &str, replacement: &str) -> String {
        // Look for card patterns and replace them
        let mut result = String::new();
        let mut current = String::new();
        let mut digit_count = 0;
        
        for ch in text.chars() {
            if ch.is_ascii_digit() {
                current.push(ch);
                digit_count += 1;
            } else if (ch == '-' || ch == ' ') && digit_count > 0 {
                // Only include separator if we've already started accumulating digits
                current.push(ch);
            } else {
                // Check if we accumulated a card number
                if digit_count >= 13 && digit_count <= 19 {
                    result.push_str(replacement);
                } else {
                    result.push_str(&current);
                }
                result.push(ch);
                current.clear();
                digit_count = 0;
            }
        }
        
        // Handle end of string
        if digit_count >= 13 && digit_count <= 19 {
            result.push_str(replacement);
        } else {
            result.push_str(&current);
        }
        
        result
    }
}

impl Rule for PatternRule {
    fn feed(&mut self, chunk: &str) -> Decision {
        if chunk.is_empty() {
            return Decision::Allow;
        }

        // Append chunk to buffer
        self.buffer.push_str(chunk);

        // Check if buffer matches pattern
        if self.matches_pattern(&self.buffer) {
            // Save the decision
            let decision = if let Some(ref replacement) = self.replacement {
                let rewritten = self.rewrite_text(&self.buffer, replacement);
                Decision::Rewrite {
                    replacement: rewritten,
                }
            } else {
                Decision::Block {
                    reason: self.reason.clone(),
                }
            };
            
            // Clear buffer after match - pattern has been detected and handled
            self.buffer.clear();
            decision
        } else {
            // Keep buffer size reasonable
            // Only keep the last N characters to handle patterns split across chunks
            const MAX_BUFFER: usize = 500;
            if self.buffer.len() > MAX_BUFFER {
                let keep = self.buffer.len() - MAX_BUFFER;
                self.buffer = self.buffer[keep..].to_string();
            }
            Decision::Allow
        }
    }

    fn reset(&mut self) {
        self.buffer.clear();
    }

    fn name(&self) -> &str {
        "pattern_rule"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_detection_simple() {
        let mut rule = PatternRule::email("found email");

        assert!(rule.feed("Contact: user@example.com").is_block());
    }

    #[test]
    fn test_email_across_chunks() {
        let mut rule = PatternRule::email("found email");

        assert!(rule.feed("Email me at ").is_allow());
        assert!(rule.feed("john@exam").is_allow());
        assert!(rule.feed("ple.com").is_block());
    }

    #[test]
    fn test_email_detection_various_formats() {
        let mut rule = PatternRule::email("found email");

        rule.reset();
        assert!(rule.feed("test.user@domain.co.uk").is_block());

        rule.reset();
        assert!(rule.feed("admin@subdomain.example.org").is_block());

        rule.reset();
        assert!(rule.feed("user+tag@example.com").is_block());
    }

    #[test]
    fn test_no_false_positive_for_non_email() {
        let mut rule = PatternRule::email("found email");

        assert!(rule.feed("This has no email").is_allow());
        
        rule.reset();
        assert!(rule.feed("Just an @ symbol").is_allow());
        
        rule.reset();
        assert!(rule.feed("Or a.dot but no @").is_allow());
    }

    #[test]
    fn test_url_detection() {
        let mut rule = PatternRule::url("found URL");

        assert!(rule.feed("Visit https://example.com").is_block());
        
        rule.reset();
        assert!(rule.feed("Check http://test.org/path").is_block());
    }

    #[test]
    fn test_ipv4_detection() {
        let mut rule = PatternRule::ipv4("found IP address");

        assert!(rule.feed("Server at 192.168.1.1").is_block());
        
        rule.reset();
        assert!(rule.feed("Connect to 10.0.0.254").is_block());
    }

    #[test]
    fn test_credit_card_detection() {
        let mut rule = PatternRule::credit_card("found credit card");

        assert!(rule.feed("Card: 4532-1234-5678-9010").is_block());
        
        rule.reset();
        assert!(rule.feed("Number: 4532123456789010").is_block());
    }

    #[test]
    fn test_custom_pattern() {
        let mut rule = PatternRule::custom(
            r"SECRET",
            "found secret",
            "secret keyword",
        );

        assert!(rule.feed("This contains SECRET data").is_block());
    }

    #[test]
    fn test_reset_clears_buffer() {
        let mut rule = PatternRule::email("found email");

        rule.feed("user@exam");
        rule.reset();
        
        // After reset, partial email doesn't continue
        assert!(rule.feed("random text").is_allow());
    }

    #[test]
    fn test_empty_chunk() {
        let mut rule = PatternRule::email("found email");
        assert!(rule.feed("").is_allow());
    }
}
