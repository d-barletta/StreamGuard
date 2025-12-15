//! Python bindings for StreamGuard using PyO3
//! 
//! Provides native Python extension with zero-copy performance

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::core::{Decision, Rule};
use crate::engine::GuardEngine as RustGuardEngine;
use crate::rules::sequence::ForbiddenSequenceRule as RustForbiddenSequenceRule;
use crate::rules::pattern::PatternRule as RustPatternRule;

/// Python wrapper for Decision
#[pyclass(name = "Decision")]
#[derive(Clone)]
pub struct PyDecision {
    inner: Decision,
}

#[pymethods]
impl PyDecision {
    fn is_allow(&self) -> bool {
        matches!(self.inner, Decision::Allow)
    }
    
    fn is_block(&self) -> bool {
        matches!(self.inner, Decision::Block { .. })
    }
    
    fn is_rewrite(&self) -> bool {
        matches!(self.inner, Decision::Rewrite { .. })
    }
    
    fn reason(&self) -> Option<String> {
        match &self.inner {
            Decision::Block { reason } => Some(reason.clone()),
            _ => None,
        }
    }
    
    fn rewritten_text(&self) -> Option<String> {
        match &self.inner {
            Decision::Rewrite { replacement } => Some(replacement.clone()),
            _ => None,
        }
    }
    
    fn __repr__(&self) -> String {
        match &self.inner {
            Decision::Allow => "Decision(Allow)".to_string(),
            Decision::Block { reason } => alloc::format!("Decision(Block, reason='{}')", reason),
            Decision::Rewrite { replacement } => alloc::format!("Decision(Rewrite, text='{}...')", 
                if replacement.len() > 20 { &replacement[..20] } else { replacement }),
        }
    }
}

/// Python wrapper for ForbiddenSequenceRule
#[pyclass(name = "ForbiddenSequenceRule")]
pub struct PyForbiddenSequenceRule {
    inner: RustForbiddenSequenceRule,
}

#[pymethods]
impl PyForbiddenSequenceRule {
    #[staticmethod]
    fn strict(tokens: Vec<String>, reason: String) -> Self {
        Self {
            inner: RustForbiddenSequenceRule::strict(tokens, reason),
        }
    }
    
    #[staticmethod]
    fn with_gaps(tokens: Vec<String>, reason: String) -> Self {
        Self {
            inner: RustForbiddenSequenceRule::with_gaps(tokens, reason),
        }
    }
    
    #[staticmethod]
    fn with_score(tokens: Vec<String>, reason: String, score: u32) -> Self {
        Self {
            inner: RustForbiddenSequenceRule::new_with_score(tokens, reason, score),
        }
    }
}

/// Python wrapper for PatternRule
#[pyclass(name = "PatternRule")]
pub struct PyPatternRule {
    inner: RustPatternRule,
}

#[pymethods]
impl PyPatternRule {
    #[staticmethod]
    fn email(reason: String) -> Self {
        Self {
            inner: RustPatternRule::email(reason),
        }
    }
    
    #[staticmethod]
    fn email_strict(reason: String) -> Self {
        Self {
            inner: RustPatternRule::email_strict(reason),
        }
    }
    
    #[staticmethod]
    fn email_rewrite(replacement: String) -> Self {
        Self {
            inner: RustPatternRule::email_rewrite(replacement),
        }
    }
    
    #[staticmethod]
    fn url(reason: String) -> Self {
        Self {
            inner: RustPatternRule::url(reason),
        }
    }
    
    #[staticmethod]
    fn url_rewrite(replacement: String) -> Self {
        Self {
            inner: RustPatternRule::url_rewrite(replacement),
        }
    }
    
    #[staticmethod]
    fn ipv4(reason: String) -> Self {
        Self {
            inner: RustPatternRule::ipv4(reason),
        }
    }
    
    #[staticmethod]
    fn ipv4_rewrite(replacement: String) -> Self {
        Self {
            inner: RustPatternRule::ipv4_rewrite(replacement),
        }
    }
    
    #[staticmethod]
    fn credit_card(reason: String) -> Self {
        Self {
            inner: RustPatternRule::credit_card(reason),
        }
    }
    
    #[staticmethod]
    fn credit_card_rewrite(replacement: String) -> Self {
        Self {
            inner: RustPatternRule::credit_card_rewrite(replacement),
        }
    }
}

/// Python wrapper for GuardEngine
#[pyclass(name = "GuardEngine")]
pub struct PyGuardEngine {
    inner: RustGuardEngine,
}

#[pymethods]
impl PyGuardEngine {
    #[new]
    fn new() -> Self {
        Self {
            inner: RustGuardEngine::new(),
        }
    }
    
    #[staticmethod]
    fn with_score_threshold(threshold: u32) -> Self {
        Self {
            inner: RustGuardEngine::with_score_threshold(threshold),
        }
    }
    
    fn add_forbidden_sequence(&mut self, rule: PyForbiddenSequenceRule) {
        self.inner.add_rule(Box::new(rule.inner));
    }
    
    fn add_pattern_rule(&mut self, rule: PyPatternRule) {
        self.inner.add_rule(Box::new(rule.inner));
    }
    
    fn feed(&mut self, chunk: &str) -> PyDecision {
        PyDecision {
            inner: self.inner.feed(chunk),
        }
    }
    
    fn reset(&mut self) {
        self.inner.reset();
    }
    
    fn current_score(&self) -> u32 {
        self.inner.current_score()
    }
    
    fn __repr__(&self) -> String {
        alloc::format!("GuardEngine(score={}, rules={})", 
            self.inner.current_score(),
            self.inner.rules.len())
    }
}

/// Python module definition
#[pymodule]
fn streamguard(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyGuardEngine>()?;
    m.add_class::<PyForbiddenSequenceRule>()?;
    m.add_class::<PyPatternRule>()?;
    m.add_class::<PyDecision>()?;
    Ok(())
}
