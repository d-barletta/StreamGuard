//! WASM bindings for browser usage

use wasm_bindgen::prelude::*;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::{GuardEngine, Decision};
use crate::rules::{ForbiddenSequenceRule, PatternRule};

/// WASM-compatible wrapper for GuardEngine
#[wasm_bindgen]
pub struct WasmGuardEngine {
    engine: GuardEngine,
}

#[wasm_bindgen]
impl WasmGuardEngine {
    /// Create a new engine
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            engine: GuardEngine::new(),
        }
    }

    /// Create an engine with score threshold
    #[wasm_bindgen(js_name = withScoreThreshold)]
    pub fn with_score_threshold(threshold: u32) -> Self {
        Self {
            engine: GuardEngine::with_score_threshold(threshold),
        }
    }

    /// Add a forbidden sequence rule
    #[wasm_bindgen(js_name = addForbiddenSequence)]
    pub fn add_forbidden_sequence(&mut self, tokens: Vec<JsValue>, reason: &str) {
        let token_strings: Vec<String> = tokens
            .iter()
            .filter_map(|v| v.as_string())
            .collect();
        
        let rule = ForbiddenSequenceRule::with_gaps(token_strings, reason);
        self.engine.add_rule(Box::new(rule));
    }

    /// Add a forbidden sequence rule with strict matching (no gaps)
    #[wasm_bindgen(js_name = addForbiddenSequenceStrict)]
    pub fn add_forbidden_sequence_strict(&mut self, tokens: Vec<JsValue>, reason: &str) {
        let token_strings: Vec<String> = tokens
            .iter()
            .filter_map(|v| v.as_string())
            .collect();
        
        let rule = ForbiddenSequenceRule::strict(token_strings, reason);
        self.engine.add_rule(Box::new(rule));
    }

    /// Add an email detection rule
    #[wasm_bindgen(js_name = addEmailBlocker)]
    pub fn add_email_blocker(&mut self, reason: &str) {
        let rule = PatternRule::email(reason);
        self.engine.add_rule(Box::new(rule));
    }

    /// Add a strict email detection rule (RFC-compliant)
    #[wasm_bindgen(js_name = addEmailBlockerStrict)]
    pub fn add_email_blocker_strict(&mut self, reason: &str) {
        let rule = PatternRule::email_strict(reason);
        self.engine.add_rule(Box::new(rule));
    }

    /// Add an email redaction rule
    #[wasm_bindgen(js_name = addEmailRedaction)]
    pub fn add_email_redaction(&mut self, replacement: &str) {
        let rule = PatternRule::email_rewrite(replacement);
        self.engine.add_rule(Box::new(rule));
    }

    /// Add a URL detection rule
    #[wasm_bindgen(js_name = addUrlBlocker)]
    pub fn add_url_blocker(&mut self, reason: &str) {
        let rule = PatternRule::url(reason);
        self.engine.add_rule(Box::new(rule));
    }

    /// Add a URL redaction rule
    #[wasm_bindgen(js_name = addUrlRedaction)]
    pub fn add_url_redaction(&mut self, replacement: &str) {
        let rule = PatternRule::url_rewrite(replacement);
        self.engine.add_rule(Box::new(rule));
    }

    /// Add an IPv4 detection rule
    #[wasm_bindgen(js_name = addIpBlocker)]
    pub fn add_ip_blocker(&mut self, reason: &str) {
        let rule = PatternRule::ipv4(reason);
        self.engine.add_rule(Box::new(rule));
    }

    /// Add an IPv4 redaction rule
    #[wasm_bindgen(js_name = addIpRedaction)]
    pub fn add_ip_redaction(&mut self, replacement: &str) {
        let rule = PatternRule::ipv4_rewrite(replacement);
        self.engine.add_rule(Box::new(rule));
    }

    /// Add a credit card detection rule
    #[wasm_bindgen(js_name = addCreditCardBlocker)]
    pub fn add_credit_card_blocker(&mut self, reason: &str) {
        let rule = PatternRule::credit_card(reason);
        self.engine.add_rule(Box::new(rule));
    }

    /// Add a credit card redaction rule
    #[wasm_bindgen(js_name = addCreditCardRedaction)]
    pub fn add_credit_card_redaction(&mut self, replacement: &str) {
        let rule = PatternRule::credit_card_rewrite(replacement);
        self.engine.add_rule(Box::new(rule));
    }

    /// Process a chunk of text
    /// Returns a JsValue with: { type: "allow" | "block" | "rewrite", reason?: string, replacement?: string }
    #[wasm_bindgen]
    pub fn feed(&mut self, chunk: &str) -> JsValue {
        let decision = self.engine.feed(chunk);
        
        match decision {
            Decision::Allow => {
                let obj = js_sys::Object::new();
                js_sys::Reflect::set(&obj, &"type".into(), &"allow".into()).unwrap();
                obj.into()
            }
            Decision::Block { reason } => {
                let obj = js_sys::Object::new();
                js_sys::Reflect::set(&obj, &"type".into(), &"block".into()).unwrap();
                js_sys::Reflect::set(&obj, &"reason".into(), &reason.into()).unwrap();
                obj.into()
            }
            Decision::Rewrite { replacement } => {
                let obj = js_sys::Object::new();
                js_sys::Reflect::set(&obj, &"type".into(), &"rewrite".into()).unwrap();
                js_sys::Reflect::set(&obj, &"replacement".into(), &replacement.into()).unwrap();
                obj.into()
            }
        }
    }

    /// Reset the engine
    #[wasm_bindgen]
    pub fn reset(&mut self) {
        self.engine.reset();
    }

    /// Check if the engine has been stopped
    #[wasm_bindgen(js_name = isStopped)]
    pub fn is_stopped(&self) -> bool {
        self.engine.is_stopped()
    }

    /// Get the current score
    #[wasm_bindgen(js_name = currentScore)]
    pub fn current_score(&self) -> u32 {
        self.engine.current_score()
    }

    /// Get the number of rules
    #[wasm_bindgen(js_name = ruleCount)]
    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }
}
