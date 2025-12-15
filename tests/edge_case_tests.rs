//! Tests for edge cases: chunk boundaries, buffer management, state reset

use streamguard::{GuardEngine, rules::{PatternRule, ForbiddenSequenceRule}};

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
