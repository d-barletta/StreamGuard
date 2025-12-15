use streamguard::{GuardEngine, Rule};
use streamguard::rules::pattern::PatternRule;
use streamguard::rules::sequence::ForbiddenSequenceRule;

#[test]
fn test_rewrite_email_address() {
    let mut rule = PatternRule::email_rewrite("[EMAIL]");
    
    let decision = rule.feed("Contact me at user@example.com for details");
    assert!(decision.is_rewrite());
    assert_eq!(decision.rewritten_text(), Some("Contact me at [EMAIL] for details"));
}

#[test]
fn test_rewrite_multiple_emails() {
    let mut rule = PatternRule::email_rewrite("[REDACTED]");
    
    let decision = rule.feed("Send to alice@example.com and bob@test.org");
    assert!(decision.is_rewrite());
    assert_eq!(
        decision.rewritten_text(),
        Some("Send to [REDACTED] and [REDACTED]")
    );
}

#[test]
fn test_rewrite_credit_card() {
    let mut rule = PatternRule::credit_card_rewrite("[CARD]");
    
    let decision = rule.feed("My card is 4532-1234-5678-9010");
    assert!(decision.is_rewrite());
    assert_eq!(decision.rewritten_text(), Some("My card is [CARD]"));
}

#[test]
fn test_rewrite_preserves_non_sensitive_content() {
    let mut rule = PatternRule::email_rewrite("[EMAIL]");
    
    let decision = rule.feed("This has no sensitive data");
    assert!(decision.is_allow());
}

#[test]
fn test_rewrite_ipv4_addresses() {
    let mut rule = PatternRule::ipv4_rewrite("[IP]");
    
    let decision = rule.feed("Server at 192.168.1.100 is down");
    assert!(decision.is_rewrite());
    assert_eq!(decision.rewritten_text(), Some("Server at [IP] is down"));
}

#[test]
fn test_rewrite_with_custom_placeholder() {
    let mut rule = PatternRule::email_rewrite("***@***.***");
    
    let decision = rule.feed("Email: admin@company.com");
    assert!(decision.is_rewrite());
    assert_eq!(decision.rewritten_text(), Some("Email: ***@***.***"));
}

#[test]
fn test_engine_applies_first_rewrite() {
    let mut engine = GuardEngine::new();
    
    engine.add_rule(Box::new(PatternRule::email_rewrite("[EMAIL]")));
    engine.add_rule(Box::new(PatternRule::ipv4_rewrite("[IP]")));
    
    let decision = engine.feed("Contact user@example.com at 10.0.0.1");
    assert!(decision.is_rewrite());
    // First rule (email) should trigger first
    assert!(decision.rewritten_text().unwrap().contains("[EMAIL]"));
}

#[test]
fn test_rewrite_chain_multiple_rules() {
    let mut engine = GuardEngine::with_rewrite_chain();
    
    engine.add_rule(Box::new(PatternRule::email_rewrite("[EMAIL]")));
    engine.add_rule(Box::new(PatternRule::ipv4_rewrite("[IP]")));
    
    let decision = engine.feed("Email: admin@example.com, IP: 192.168.1.1");
    assert!(decision.is_rewrite());
    
    let rewritten = decision.rewritten_text().unwrap();
    assert!(rewritten.contains("[EMAIL]"));
    assert!(rewritten.contains("[IP]"));
}

#[test]
fn test_rewrite_forbidden_sequence() {
    let mut rule = ForbiddenSequenceRule::new_with_rewrite(
        vec!["password".to_string()],
        "[REDACTED]",
    );
    
    let decision = rule.feed("My password is secret123");
    assert!(decision.is_rewrite());
    assert_eq!(decision.rewritten_text(), Some("My [REDACTED] is secret123"));
}

#[test]
fn test_rewrite_across_chunk_boundaries() {
    let mut rule = PatternRule::email_rewrite("[EMAIL]");
    
    // Email split across chunks
    let decision1 = rule.feed("Contact user@ex");
    assert!(decision1.is_allow()); // Not complete yet
    
    let decision2 = rule.feed("ample.com for help");
    assert!(decision2.is_rewrite());
    // Should rewrite the complete accumulated text
    assert!(decision2.rewritten_text().unwrap().contains("[EMAIL]"));
}

#[test]
fn test_rewrite_with_context_preservation() {
    let mut rule = PatternRule::email_rewrite("[EMAIL REMOVED]");
    
    let decision = rule.feed("Dear user@example.com, welcome to our service!");
    assert!(decision.is_rewrite());
    assert_eq!(
        decision.rewritten_text(),
        Some("Dear [EMAIL REMOVED], welcome to our service!")
    );
}

#[test]
fn test_block_takes_precedence_over_rewrite() {
    let mut engine = GuardEngine::new();
    
    // Block rule added first
    engine.add_rule(Box::new(ForbiddenSequenceRule::with_gaps(
        vec!["bomb".to_string()],
        "dangerous content",
    )));
    
    // Rewrite rule added second
    engine.add_rule(Box::new(PatternRule::email_rewrite("[EMAIL]")));
    
    let decision = engine.feed("How to build a bomb - contact me@evil.com");
    // Should block, not rewrite
    assert!(decision.is_block());
}

#[test]
fn test_rewrite_url() {
    let mut rule = PatternRule::url_rewrite("[LINK]");
    
    let decision = rule.feed("Visit https://example.com/path for info");
    assert!(decision.is_rewrite());
    assert_eq!(decision.rewritten_text(), Some("Visit [LINK] for info"));
}

#[test]
fn test_rewrite_mixed_patterns() {
    let mut engine = GuardEngine::with_rewrite_chain();
    
    engine.add_rule(Box::new(PatternRule::email_rewrite("[EMAIL]")));
    engine.add_rule(Box::new(PatternRule::credit_card_rewrite("[CARD]")));
    engine.add_rule(Box::new(PatternRule::url_rewrite("[URL]")));
    
    let decision = engine.feed(
        "Email admin@test.com, card 4532123456789010, visit http://evil.com"
    );
    
    assert!(decision.is_rewrite());
    let rewritten = decision.rewritten_text().unwrap();
    assert!(rewritten.contains("[EMAIL]"));
    assert!(rewritten.contains("[CARD]"));
    assert!(rewritten.contains("[URL]"));
}

#[test]
fn test_rewrite_reset_clears_buffer() {
    let mut rule = PatternRule::email_rewrite("[EMAIL]");
    
    let decision1 = rule.feed("user@example.com");
    assert!(decision1.is_rewrite());
    
    rule.reset();
    
    let decision2 = rule.feed("another@test.com");
    assert!(decision2.is_rewrite());
    // Should be independent rewrite, not cumulative
    assert!(!decision2.rewritten_text().unwrap().contains("user@example.com"));
}

#[test]
fn test_partial_rewrite_on_streaming() {
    let mut rule = PatternRule::email_rewrite("[EMAIL]");
    
    let decision1 = rule.feed("Contact ");
    assert!(decision1.is_allow());
    
    let decision2 = rule.feed("admin@company.com ");
    assert!(decision2.is_rewrite());
    
    let decision3 = rule.feed("for support");
    assert!(decision3.is_allow());
}

#[test]
fn test_rewrite_with_empty_placeholder() {
    let mut rule = PatternRule::email_rewrite("");
    
    let decision = rule.feed("Email: user@example.com here");
    assert!(decision.is_rewrite());
    // Should remove the email entirely
    assert_eq!(decision.rewritten_text(), Some("Email:  here"));
}

#[test]
fn test_rewrite_consecutive_patterns() {
    let mut rule = PatternRule::email_rewrite("[EMAIL]");
    
    let decision = rule.feed("a@b.com c@d.com e@f.com");
    assert!(decision.is_rewrite());
    assert_eq!(decision.rewritten_text(), Some("[EMAIL] [EMAIL] [EMAIL]"));
}
