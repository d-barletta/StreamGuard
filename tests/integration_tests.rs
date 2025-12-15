//! Integration tests for StreamGuard
//!
//! These tests verify the streaming behavior of the engine
//! with real rules, focusing on chunk boundaries and state management.

use streamguard::{GuardEngine, rules::{ForbiddenSequenceRule, SequenceConfig, PatternRule, PatternPreset}};

#[test]
fn test_streaming_forbidden_sequence() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["how", "to", "build", "bomb"],
        "forbidden content",
    )));

    // Simulate streaming LLM output
    let chunks = vec!["how ", "to ", "bu", "ild ", "a ", "bomb"];

    let mut blocked = false;
    for chunk in chunks {
        let decision = engine.feed(chunk);
        if decision.is_block() {
            blocked = true;
            break;
        }
    }

    assert!(blocked, "Should have blocked the forbidden sequence");
}

#[test]
fn test_streaming_safe_content() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["forbidden", "sequence"],
        "test",
    )));

    let chunks = vec![
        "This is ",
        "perfectly ",
        "safe ",
        "content ",
        "for streaming",
    ];

    for chunk in chunks {
        let decision = engine.feed(chunk);
        assert!(decision.is_allow(), "Safe content should be allowed");
    }
}

#[test]
fn test_multiple_rules() {
    let mut engine = GuardEngine::new();

    // Add multiple rules
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["bad", "word"],
        "profanity",
    )));

    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["secret", "key"],
        "data leak",
    )));

    // Should block on first rule
    assert!(engine.feed("bad ").is_allow());
    assert!(engine.feed("word").is_block());
}

#[test]
fn test_reset_between_streams() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["how", "to", "hack"],
        "security",
    )));

    // First stream - partial match
    assert!(engine.feed("how to ").is_allow());

    // Reset before new stream
    engine.reset();

    // Second stream - should start fresh
    assert!(engine.feed("completely different").is_allow());
    assert!(engine.feed("safe content").is_allow());
}

#[test]
fn test_chunk_boundary_edge_cases() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["test"],
        "found test",
    )));

    // Token split across chunks
    assert!(engine.feed("te").is_allow());
    assert!(engine.feed("st").is_block());
}

#[test]
fn test_very_small_chunks() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["xyz"],
        "found xyz",
    )));

    // Single character chunks
    assert!(engine.feed("x").is_allow());
    assert!(engine.feed("y").is_allow());
    assert!(engine.feed("z").is_block());
}

#[test]
fn test_negation_breaks_sequence() {
    let mut engine = GuardEngine::new();
    
    // With stop words configured
    let config = SequenceConfig::new().stop_words(vec!["not", "never"]);
    engine.add_rule(Box::new(ForbiddenSequenceRule::new(
        vec!["how", "to", "build", "bomb"],
        "weapon instructions",
        config,
    )));

    // "not" now breaks the sequence
    assert!(engine.feed("how ").is_allow());
    assert!(engine.feed("to not ").is_allow());
    assert!(engine.feed("build a ").is_allow());
    assert!(engine.feed("bomb").is_allow()); // Stop word reset the sequence
}

#[test]
fn test_negation_breaks_sequence_default_behavior() {
    let mut engine = GuardEngine::new();
    
    // Default behavior (no stop words) - tokens found with gaps
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["how", "to", "build", "bomb"],
        "weapon instructions",
    )));

    // Without stop words, "not" does NOT break the sequence
    assert!(engine.feed("how ").is_allow());
    assert!(engine.feed("to not ").is_allow());
    assert!(engine.feed("build a ").is_allow());
    
    // This WILL block because all tokens appeared in order
    let decision = engine.feed("bomb");
    assert!(decision.is_block(), "Default behavior allows gaps");
}

#[test]
fn test_strict_consecutive_sequence() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::strict(
        vec!["password", "is"],
        "credential leak",
    )));

    // Tokens appear consecutively - should block
    assert!(engine.feed("password ").is_allow());
    assert!(engine.feed("is").is_block());
}

#[test]
fn test_strict_mode_rejects_gaps() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::strict(
        vec!["secret", "key"],
        "data leak",
    )));

    // Gap between tokens - should not block in strict mode
    assert!(engine.feed("secret ").is_allow());
    assert!(engine.feed("encryption key").is_allow());
}

#[test]
fn test_tokens_with_gaps_still_match() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["steal", "password"],
        "security threat",
    )));

    // Default behavior: tokens found even with words in between
    assert!(engine.feed("don't steal ").is_allow());
    assert!(engine.feed("anyone's password").is_block());
}

#[test]
fn test_stop_words_prevent_match() {
    let mut engine = GuardEngine::new();
    
    let config = SequenceConfig::new().stop_words(vec!["not", "never", "don't"]);
    engine.add_rule(Box::new(ForbiddenSequenceRule::new(
        vec!["steal", "password"],
        "security threat",
        config,
    )));

    // Stop word "don't" resets the sequence
    assert!(engine.feed("don't steal ").is_allow());
    assert!(engine.feed("password").is_allow());
}

#[test]
fn test_order_matters() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["first", "second", "third"],
        "sequence test",
    )));

    // Wrong order - should not match
    assert!(engine.feed("third ").is_allow());
    assert!(engine.feed("second ").is_allow());
    assert!(engine.feed("first").is_allow());
    
    engine.reset();
    
    // Correct order - should match
    assert!(engine.feed("first ").is_allow());
    assert!(engine.feed("second ").is_allow());
    assert!(engine.feed("third").is_block());
}

#[test]
fn test_stop_words_streaming() {
    let mut engine = GuardEngine::new();
    
    let config = SequenceConfig::new().stop_words(vec!["never"]);
    engine.add_rule(Box::new(ForbiddenSequenceRule::new(
        vec!["hack", "into", "system"],
        "unauthorized access",
        config,
    )));

    // Sequence starts
    assert!(engine.feed("hack ").is_allow());
    assert!(engine.feed("into ").is_allow());
    
    // "never" appears and resets
    assert!(engine.feed("but never ").is_allow());
    
    // Even though "system" appears later, sequence was reset
    assert!(engine.feed("into the system").is_allow());
}

#[test]
fn test_combined_strict_and_stop_words() {
    let mut engine = GuardEngine::new();
    
    let config = SequenceConfig::strict().stop_words(vec!["not"]);
    engine.add_rule(Box::new(ForbiddenSequenceRule::new(
        vec!["execute", "command"],
        "code execution",
        config,
    )));

    // Consecutive tokens without stop words - blocks
    engine.reset();
    assert!(engine.feed("execute ").is_allow());
    assert!(engine.feed("command").is_block());
    
    // With stop word - doesn't block
    engine.reset();
    assert!(engine.feed("execute not ").is_allow());
    assert!(engine.feed("command").is_allow());
}

// Pattern matching tests

#[test]
fn test_email_detection_streaming() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email detected")));

    // Email split across chunks
    assert!(engine.feed("Contact me at ").is_allow());
    assert!(engine.feed("john").is_allow());
    assert!(engine.feed("@example").is_allow());
    
    let decision = engine.feed(".com for info");
    assert!(decision.is_block(), "Should detect email across chunks");
}

#[test]
fn test_email_simple_usage() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("found email")));

    // Single chunk with email
    assert!(engine.feed("My email is user@domain.com").is_block());
}

#[test]
fn test_email_strict_mode() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email_strict("email leak")));

    assert!(engine.feed("admin@company.org").is_block());
}

#[test]
fn test_url_detection() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::url("URL detected")));

    assert!(engine.feed("Visit https://example.com").is_block());
}

#[test]
fn test_ipv4_detection() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::ipv4("IP address detected")));

    assert!(engine.feed("Server: 192.168.1.1").is_block());
}

#[test]
fn test_credit_card_detection() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::credit_card("credit card detected")));

    assert!(engine.feed("Card: 4532-1234-5678-9010").is_block());
}

#[test]
fn test_pattern_from_preset() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::from_preset(
        PatternPreset::Email,
        "email found"
    )));

    assert!(engine.feed("test@example.com").is_block());
}

#[test]
fn test_custom_pattern() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::custom(
        "CONFIDENTIAL",
        "found confidential marker",
        "confidential keyword"
    )));

    assert!(engine.feed("This is CONFIDENTIAL data").is_block());
}

#[test]
fn test_multiple_pattern_rules() {
    let mut engine = GuardEngine::new();
    
    engine.add_rule(Box::new(PatternRule::email("email")));
    engine.add_rule(Box::new(PatternRule::url("url")));
    engine.add_rule(Box::new(PatternRule::ipv4("ip")));

    // Test email blocks
    assert!(engine.feed("Contact: user@example.com").is_block());
    
    // Test URL blocks (new stream)
    engine.reset();
    assert!(engine.feed("Visit https://test.com").is_block());
    
    // Test IP blocks (new stream)
    engine.reset();
    assert!(engine.feed("Server: 10.0.0.1").is_block());
}

#[test]
fn test_pattern_with_sequence_rules() {
    let mut engine = GuardEngine::new();
    
    // Mix pattern and sequence rules
    engine.add_rule(Box::new(PatternRule::email("email leak")));
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["password", "is"],
        "credential leak"
    )));

    // Pattern rule should catch email
    assert!(engine.feed("Email: admin@company.com").is_block());
    
    // Sequence rule should catch password sequence
    engine.reset();
    assert!(engine.feed("The password ").is_allow());
    assert!(engine.feed("is secret123").is_block());
}

#[test]
fn test_pattern_no_false_positives() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email")));

    // These should not trigger
    assert!(engine.feed("No email here").is_allow());
    
    engine.reset();
    assert!(engine.feed("Just an @ symbol").is_allow());
    
    engine.reset();
    assert!(engine.feed("Or a.dot without @").is_allow());
}
