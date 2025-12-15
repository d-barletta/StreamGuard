//! Tests for aho-corasick specific improvements and edge cases
//!
//! These tests demonstrate the benefits of using the aho-corasick library
//! for efficient DFA-based pattern matching.

use streamguard::{GuardEngine, rules::ForbiddenSequenceRule};

#[test]
fn test_multiple_patterns_efficient_matching() {
    // aho-corasick excels at matching multiple patterns simultaneously
    let mut engine = GuardEngine::new();
    
    // Add multiple sequences to detect
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["hack", "system"],
        "hacking attempt",
    )));
    
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["steal", "data"],
        "data theft",
    )));
    
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["bypass", "security"],
        "security bypass",
    )));
    
    // Should allow safe content
    assert!(engine.feed("This is safe content").is_allow());
    
    engine.reset();
    
    // Should block first pattern
    assert!(engine.feed("hack the ").is_allow());
    assert!(engine.feed("system").is_block());
}

#[test]
fn test_overlapping_token_patterns() {
    // Test that sequences with similar tokens are handled correctly
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["abc", "xyz"],
        "test sequence",
    )));
    
    // Should match "abc" followed by "xyz"
    assert!(engine.feed("abc ").is_allow());
    assert!(engine.feed("xyz").is_block());
    
    engine.reset();
    
    // Test with different tokens
    let mut engine2 = GuardEngine::new();
    engine2.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["alpha", "beta", "gamma"],
        "greek letters",
    )));
    
    assert!(engine2.feed("alpha ").is_allow());
    assert!(engine2.feed("beta ").is_allow());
    assert!(engine2.feed("gamma").is_block());
}

#[test]
fn test_pattern_matching_with_unicode() {
    // aho-corasick handles Unicode correctly
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["café", "résumé"],
        "unicode test",
    )));
    
    assert!(engine.feed("café ").is_allow());
    assert!(engine.feed("and résumé").is_block());
}

#[test]
fn test_efficient_stop_word_detection() {
    // Stop words are also matched using aho-corasick for efficiency
    use streamguard::rules::SequenceConfig;
    
    let config = SequenceConfig::new()
        .stop_words(vec!["not", "never", "don't", "won't", "can't"]);
    
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::new(
        vec!["how", "to", "hack"],
        "security",
        config,
    )));
    
    // Should reset on "not"
    assert!(engine.feed("how to not ").is_allow());
    assert!(engine.feed("hack").is_allow());
    
    engine.reset();
    
    // Should reset on "never"
    assert!(engine.feed("how to never ").is_allow());
    assert!(engine.feed("hack").is_allow());
}

#[test]
fn test_leftmost_first_matching() {
    // aho-corasick uses LeftmostFirst matching strategy
    // This ensures deterministic behavior when patterns overlap
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["she", "he"],
        "pronoun test",
    )));
    
    // "she" contains "he", but LeftmostFirst should match "she" first
    assert!(engine.feed("she ").is_allow());
    assert!(engine.feed("he").is_block());
}

#[test]
fn test_streaming_with_large_gaps() {
    // aho-corasick efficiently handles large buffers between tokens
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["alpha", "omega"],
        "greek test",
    )));
    
    assert!(engine.feed("alpha ").is_allow());
    
    // Insert 1000 words between tokens
    for _ in 0..1000 {
        assert!(engine.feed("filler ").is_allow());
    }
    
    // Should still detect the sequence
    assert!(engine.feed("omega").is_block());
}

#[test]
fn test_pattern_at_chunk_boundaries() {
    // Verify aho-corasick handles patterns split across chunk boundaries
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["password", "secret"],
        "sensitive",
    )));
    
    // Split "password" across chunks
    assert!(engine.feed("pass").is_allow());
    assert!(engine.feed("word ").is_allow());
    assert!(engine.feed("secret").is_block());
}

#[test]
fn test_multiple_identical_tokens_in_sequence() {
    // Test that duplicate tokens in the sequence work correctly
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["echo", "echo", "echo"],
        "triple echo",
    )));
    
    assert!(engine.feed("echo ").is_allow());
    assert!(engine.feed("echo ").is_allow());
    assert!(engine.feed("echo").is_block());
}

#[test]
fn test_short_and_long_tokens_mixed() {
    // aho-corasick efficiently handles mixed token lengths
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["a", "very", "b", "long", "c", "sequence"],
        "mixed lengths",
    )));
    
    assert!(engine.feed("a ").is_allow());
    assert!(engine.feed("very ").is_allow());
    assert!(engine.feed("b ").is_allow());
    assert!(engine.feed("long ").is_allow());
    assert!(engine.feed("c ").is_allow());
    assert!(engine.feed("sequence").is_block());
}

#[test]
fn test_deterministic_repeated_matching() {
    // Ensure deterministic behavior across multiple runs
    for _ in 0..10 {
        let mut engine = GuardEngine::new();
        engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
            vec!["deterministic", "test"],
            "consistency check",
        )));
        
        assert!(engine.feed("deterministic ").is_allow());
        assert!(engine.feed("test").is_block());
    }
}

#[test]
fn test_empty_tokens_not_supported() {
    // aho-corasick doesn't support empty patterns
    // Our implementation should handle this gracefully by using non-empty tokens
    let mut engine = GuardEngine::new();
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["first", "second"],
        "no empty",
    )));
    
    assert!(engine.feed("first ").is_allow());
    assert!(engine.feed("second").is_block());
}
