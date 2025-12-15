use streamguard::GuardEngine;
use streamguard::rules::sequence::ForbiddenSequenceRule;

// Note: For scoring to work, rules need to support it, and engine needs
// to be configured with scoring enabled. The API uses engine methods for scores.

#[test]
fn test_engine_accumulates_scores() {
    let mut engine = GuardEngine::new();
    
    engine.add_rule(Box::new(ForbiddenSequenceRule::new_with_score(
        vec!["hack".to_string()],
        "hacking content",
        50,
    )));
    
    engine.add_rule(Box::new(ForbiddenSequenceRule::new_with_score(
        vec!["password".to_string()],
        "sensitive data",
        30,
    )));
    
    let decision = engine.feed("how to hack a password");
    assert!(decision.is_block());
    
    // Check score through engine
    assert_eq!(engine.current_score(), 80);
}

#[test]
fn test_score_threshold_blocking() {
    let mut engine = GuardEngine::with_score_threshold(60);
    
    engine.add_rule(Box::new(ForbiddenSequenceRule::new_with_score(
        vec!["suspicious".to_string()],
        "suspicious content",
        40,
    )));
    
    // Below threshold - should allow
    let decision = engine.feed("this is suspicious");
    assert!(decision.is_allow());
    assert_eq!(engine.current_score(), 40);
}

#[test]
fn test_score_threshold_triggers_block() {
    let mut engine = GuardEngine::with_score_threshold(50);
    
    engine.add_rule(Box::new(ForbiddenSequenceRule::new_with_score(
        vec!["malware".to_string()],
        "malware detected",
        75,
    )));
    
    // Above threshold - should block
    let decision = engine.feed("download this malware");
    assert!(decision.is_block());
    assert_eq!(engine.current_score(), 75);
}

#[test]
fn test_multiple_rules_cumulative_score_exceeds_threshold() {
    let mut engine = GuardEngine::with_score_threshold(100);
    
    engine.add_rule(Box::new(ForbiddenSequenceRule::new_with_score(
        vec!["hack".to_string()],
        "hacking",
        60,
    )));
    
    engine.add_rule(Box::new(ForbiddenSequenceRule::new_with_score(
        vec!["exploit".to_string()],
        "exploit",
        50,
    )));
    
    // Neither alone exceeds threshold, but together they do
    let decision = engine.feed("hack and exploit");
    assert!(decision.is_block());
    assert_eq!(engine.current_score(), 110);
}

#[test]
fn test_score_details_per_rule() {
    let mut engine = GuardEngine::new();
    
    engine.add_rule(Box::new(ForbiddenSequenceRule::new_with_score(
        vec!["virus".to_string()],
        "virus detected",
        80,
    )));
    
    engine.add_rule(Box::new(ForbiddenSequenceRule::new_with_score(
        vec!["trojan".to_string()],
        "trojan detected",
        70,
    )));
    
    let _decision = engine.feed("virus and trojan code");
    
    let score_details = engine.score_details();
    assert_eq!(score_details.len(), 2);
    assert!(score_details.iter().any(|(name, score)| name.contains("forbidden") && *score == 80));
    assert!(score_details.iter().any(|(name, score)| name.contains("forbidden") && *score == 70));
}

#[test]
fn test_score_decay_across_chunks() {
    let mut engine = GuardEngine::with_score_decay(0.5);
    
    engine.add_rule(Box::new(ForbiddenSequenceRule::new_with_score(
        vec!["suspicious".to_string()],
        "suspicious",
        100,
    )));
    
    // First chunk triggers score
    let _decision1 = engine.feed("suspicious activity");
    assert_eq!(engine.current_score(), 100);
    
    // Second chunk - score should decay by 50%
    let _decision2 = engine.feed(" more content");
    assert_eq!(engine.current_score(), 50);
    
    // Third chunk - score decays further
    let _decision3 = engine.feed(" even more");
    assert_eq!(engine.current_score(), 25);
}

#[test]
fn test_score_reset() {
    let mut engine = GuardEngine::new();
    
    engine.add_rule(Box::new(ForbiddenSequenceRule::new_with_score(
        vec!["bad".to_string()],
        "bad word",
        50,
    )));
    
    let _decision1 = engine.feed("bad content");
    assert_eq!(engine.current_score(), 50);
    
    engine.reset();
    
    let _decision2 = engine.feed("good content");
    assert_eq!(engine.current_score(), 0);
}

#[test]
fn test_weighted_scoring() {
    let mut engine = GuardEngine::new();
    
    // Critical severity
    engine.add_rule(Box::new(ForbiddenSequenceRule::new_with_score(
        vec!["kill".to_string(), "process".to_string()],
        "critical command",
        100,
    )));
    
    // Medium severity
    engine.add_rule(Box::new(ForbiddenSequenceRule::new_with_score(
        vec!["delete".to_string()],
        "medium risk",
        50,
    )));
    
    // Low severity
    engine.add_rule(Box::new(ForbiddenSequenceRule::new_with_score(
        vec!["warning".to_string()],
        "low risk",
        10,
    )));
    
    let _decision = engine.feed("warning: delete or kill the process");
    assert_eq!(engine.current_score(), 160);
}
