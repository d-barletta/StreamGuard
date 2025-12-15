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

// Edge case tests

#[test]
fn test_pattern_split_across_many_chunks() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email")));

    // Split email character by character
    assert!(engine.feed("u").is_allow());
    assert!(engine.feed("s").is_allow());
    assert!(engine.feed("e").is_allow());
    assert!(engine.feed("r").is_allow());
    assert!(engine.feed("@").is_allow());
    assert!(engine.feed("e").is_allow());
    assert!(engine.feed("x").is_allow());
    assert!(engine.feed("a").is_allow());
    assert!(engine.feed("m").is_allow());
    assert!(engine.feed("p").is_allow());
    assert!(engine.feed("l").is_allow());
    assert!(engine.feed("e").is_allow());
    assert!(engine.feed(".").is_allow());
    assert!(engine.feed("c").is_allow());
    
    // After "c", we have "user@example.c" which is not yet a valid email
    let decision = engine.feed("o");
    // After "o", we have "user@example.co" which might be detected
    // Continue to complete
    if decision.is_allow() {
        assert!(engine.feed("m").is_block());
    }
}

#[test]
fn test_multiple_patterns_in_single_chunk() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email")));

    // First email should block immediately
    assert!(engine.feed("Emails: user@test.com and admin@test.com").is_block());
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
fn test_sequence_tokens_as_substrings() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["test", "testing"],
        "sequence"
    )));

    // "test" appears but not as separate token
    assert!(engine.feed("testing is fun").is_allow());
}

#[test]
fn test_sequence_duplicate_tokens() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["repeat", "repeat"],
        "duplicate"
    )));

    assert!(engine.feed("repeat ").is_allow());
    assert!(engine.feed("repeat").is_block());
}

#[test]
fn test_empty_chunks_between_matches() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["first", "second"],
        "test"
    )));

    assert!(engine.feed("first").is_allow());
    assert!(engine.feed("").is_allow());
    assert!(engine.feed("").is_allow());
    assert!(engine.feed("second").is_block());
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
fn test_buffer_overflow_prevention() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email")));

    // Feed very large chunk without pattern
    let large_text = "a".repeat(10000);
    assert!(engine.feed(&large_text).is_allow());
    
    // Pattern should still be detected after large text
    assert!(engine.feed(" user@example.com").is_block());
}

#[test]
fn test_sequence_very_long_gap() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["start", "end"],
        "test"
    )));

    assert!(engine.feed("start ").is_allow());
    
    // Very long text between tokens
    let filler = " word ".repeat(500);
    assert!(engine.feed(&filler).is_allow());
    
    assert!(engine.feed("end").is_block());
}

#[test]
fn test_strict_mode_whitespace_only_gap() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::strict(
        vec!["one", "two"],
        "test"
    )));

    // Multiple spaces (whitespace only) should be allowed in strict mode
    assert!(engine.feed("one   ").is_allow());
    assert!(engine.feed("  two").is_block());
}

#[test]
fn test_strict_mode_newline_between_tokens() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::strict(
        vec!["line", "break"],
        "test"
    )));

    assert!(engine.feed("line\n").is_allow());
    assert!(engine.feed("break").is_block());
}

#[test]
fn test_reset_during_partial_pattern_match() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::email("email")));

    assert!(engine.feed("user@exam").is_allow());
    
    // Reset mid-pattern
    engine.reset();
    
    // Continuing shouldn't complete the pattern
    assert!(engine.feed("ple.com").is_allow());
}

#[test]
fn test_reset_during_partial_sequence_match() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["one", "two", "three"],
        "test"
    )));

    assert!(engine.feed("one two ").is_allow());
    
    // Reset before completing sequence
    engine.reset();
    
    // "three" alone shouldn't block
    assert!(engine.feed("three").is_allow());
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
fn test_stop_word_at_chunk_boundary() {
    let mut engine = GuardEngine::new();
    let config = SequenceConfig::new().stop_words(vec!["not"]);
    engine.add_rule(Box::new(ForbiddenSequenceRule::new(
        vec!["do", "harm"],
        "threat",
        config,
    )));

    assert!(engine.feed("do ").is_allow());
    assert!(engine.feed("no").is_allow());
    assert!(engine.feed("t harm").is_allow()); // "not" split across chunks
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

#[test]
fn test_sequence_case_sensitivity() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["secret", "password"],
        "test"
    )));

    // Different case - should still match (substring matching is case-sensitive by default)
    assert!(engine.feed("secret ").is_allow());
    assert!(engine.feed("password").is_block());
    
    engine.reset();
    
    // Mixed case in text
    assert!(engine.feed("SECRET ").is_allow());
    assert!(engine.feed("PASSWORD").is_allow()); // Won't match due to case
}

#[test]
fn test_single_character_tokens() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["a", "b", "c"],
        "test"
    )));

    assert!(engine.feed("a ").is_allow());
    assert!(engine.feed("b ").is_allow());
    assert!(engine.feed("c").is_block());
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
fn test_sequence_all_tokens_in_one_word() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["cat", "dog"],
        "test"
    )));

    // Both tokens as substrings of one word
    assert!(engine.feed("catalog").is_allow());
}

#[test]
fn test_ipv4_valid_in_text() {
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(PatternRule::ipv4("ip")));

    // Valid IPv4 should be detected even with extra text
    assert!(engine.feed("IP: 192.168.1.1 is valid").is_block());
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
