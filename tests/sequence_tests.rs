//! Tests for basic sequence matching functionality

use streamguard::{GuardEngine, rules::ForbiddenSequenceRule};

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
