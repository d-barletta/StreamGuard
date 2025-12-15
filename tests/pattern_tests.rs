//! Tests for pattern matching (email, URL, IP, credit card detection)

use streamguard::{GuardEngine, rules::{PatternRule, PatternPreset}};

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
fn test_pattern_at_chunk_boundary() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email")));

    // Split right at the @ symbol
    assert!(engine.feed("user").is_allow());
    assert!(engine.feed("@example.com").is_block());
}

#[test]
fn test_very_long_email() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email")));

    let long_email = format!("{}@example.com", "a".repeat(100));
    assert!(engine.feed(&long_email).is_block());
}

#[test]
fn test_pattern_with_special_characters() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email")));

    assert!(engine.feed("user+tag@example.com").is_block());
    
    engine.reset();
    assert!(engine.feed("user.name@sub.domain.com").is_block());
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
fn test_ipv4_valid_in_text() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::ipv4("ip")));

    // Valid IPv4 should be detected even with extra text
    assert!(engine.feed("IP: 192.168.1.1 is valid").is_block());
}

#[test]
fn test_credit_card_detection() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::credit_card("credit card detected")));

    assert!(engine.feed("Card: 4532-1234-5678-9010").is_block());
}

#[test]
fn test_credit_card_with_various_separators() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::credit_card("cc")));

    assert!(engine.feed("4532-1234-5678-9010").is_block());
    
    engine.reset();
    assert!(engine.feed("4532 1234 5678 9010").is_block());
    
    engine.reset();
    assert!(engine.feed("4532123456789010").is_block());
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
fn test_multiple_patterns_in_single_chunk() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email")));

    // First email should block immediately
    assert!(engine.feed("Emails: user@test.com and admin@test.com").is_block());
}

#[test]
fn test_overlapping_patterns() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email")));

    // Text that could form email in different ways
    assert!(engine.feed("test@domain.com@fake.org").is_block());
}

#[test]
fn test_pattern_at_end_of_stream() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email")));

    assert!(engine.feed("The email is ").is_allow());
    assert!(engine.feed("user@example.com").is_block());
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

#[test]
fn test_pattern_false_start() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email")));

    // Looks like it might be an email but isn't
    assert!(engine.feed("not@").is_allow());
    assert!(engine.feed("an").is_allow());
    assert!(engine.feed("email").is_allow());
}
