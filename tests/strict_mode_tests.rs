//! Tests for strict mode (no gaps allowed) and stop words functionality

use streamguard::{GuardEngine, rules::{ForbiddenSequenceRule, SequenceConfig}};

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
