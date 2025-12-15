//! Tests for combining multiple rules and rule types

use streamguard::{GuardEngine, rules::{PatternRule, ForbiddenSequenceRule}};

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
fn test_multiple_rules_same_chunk() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email")));
    engine.add_rule(Box::new(PatternRule::url("url")));
    engine.add_rule(Box::new(PatternRule::ipv4("ip")));

    // First matching rule blocks
    assert!(engine.feed("test@example.com").is_block());
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
