package com.streamguard.examples;

import com.streamguard.*;
import java.util.Arrays;
import java.util.List;

/**
 * StreamGuard Java Examples
 * Demonstrates using StreamGuard native JNI bindings
 */
public class Demo {
    
    public static void example1BasicBlocking() {
        System.out.println("\n=== Example 1: Basic Forbidden Sequence ===");
        
        try (GuardEngine engine = new GuardEngine()) {
            // Add a rule to block weapon-related instructions
            ForbiddenSequenceRule rule = ForbiddenSequenceRule.withGaps(
                new String[]{"how", "to", "build", "bomb"},
                "forbidden weapons instructions"
            );
            engine.addForbiddenSequence(rule);
            
            // Test with benign text
            Decision safe = engine.feed("How to build a web application");
            System.out.println("Safe text: " + safe);
            
            // Reset for next test
            engine.reset();
            
            // Test with forbidden sequence
            String[] chunks = {"How ", "to ", "build ", "a ", "bomb"};
            for (String chunk : chunks) {
                Decision decision = engine.feed(chunk);
                if (decision.isBlock()) {
                    System.out.println("🚫 Blocked: " + decision.getReason());
                    break;
                }
            }
        }
    }
    
    public static void example2EmailRedaction() {
        System.out.println("\n=== Example 2: Email Redaction ===");
        
        try (GuardEngine engine = new GuardEngine()) {
            // Add email redaction rule
            PatternRule emailRule = PatternRule.emailRewrite("[EMAIL_REDACTED]");
            engine.addPatternRule(emailRule);
            
            String text = "Contact me at john@example.com for details";
            Decision decision = engine.feed(text);
            
            if (decision.isRewrite()) {
                System.out.println("Original: " + text);
                System.out.println("Redacted: " + decision.getRewrittenText());
            }
        }
    }
    
    public static void example3ScoringSystem() {
        System.out.println("\n=== Example 3: Scoring System ===");
        
        try (GuardEngine engine = GuardEngine.withScoreThreshold(100)) {
            // Add multiple rules with scores
            ForbiddenSequenceRule rule1 = ForbiddenSequenceRule.withScore(
                new String[]{"password", "is"},
                "credential leak",
                50
            );
            ForbiddenSequenceRule rule2 = ForbiddenSequenceRule.withScore(
                new String[]{"secret", "key"},
                "secret exposure",
                50
            );
            
            engine.addForbiddenSequence(rule1);
            engine.addForbiddenSequence(rule2);
            
            System.out.println("Score threshold: 100");
            System.out.println("Processing chunks...");
            
            String[] chunks = {
                "The password is secret123",
                " and the secret key is xyz"
            };
            
            for (String chunk : chunks) {
                Decision decision = engine.feed(chunk);
                System.out.println("Score: " + engine.currentScore() + " " + decision);
                
                if (decision.isBlock()) {
                    System.out.println("🚫 Blocked due to score threshold!");
                    break;
                }
            }
        }
    }
    
    public static void example4StreamingLlm() {
        System.out.println("\n=== Example 4: Streaming LLM Simulation ===");
        
        try (GuardEngine engine = new GuardEngine()) {
            // Add various safety rules
            engine.addPatternRule(PatternRule.emailRewrite("[EMAIL]"));
            engine.addPatternRule(PatternRule.urlRewrite("[URL]"));
            engine.addForbiddenSequence(
                ForbiddenSequenceRule.withGaps(
                    new String[]{"how", "to", "hack"},
                    "security violation"
                )
            );
            
            // Simulate LLM streaming response
            String llmResponse = "You can learn more at https://example.com or email me at admin@site.com";
            int chunkSize = 10;
            
            System.out.println("Original response: " + llmResponse);
            System.out.println("Streaming with guardrails:");
            
            StringBuilder output = new StringBuilder();
            for (int i = 0; i < llmResponse.length(); i += chunkSize) {
                String chunk = llmResponse.substring(i, Math.min(i + chunkSize, llmResponse.length()));
                Decision decision = engine.feed(chunk);
                
                if (decision.isAllow()) {
                    output.append(chunk);
                    System.out.print(chunk);
                } else if (decision.isRewrite()) {
                    output = new StringBuilder(decision.getRewrittenText());
                    System.out.println("\n[Content rewritten]");
                    System.out.println(output);
                    break;
                } else if (decision.isBlock()) {
                    System.out.println("\n🚫 Stream blocked: " + decision.getReason());
                    break;
                }
            }
            System.out.println();
        }
    }
    
    public static void example5ServletFilter() {
        System.out.println("\n=== Example 5: Servlet Filter Pattern ===");
        
        // Guard middleware class
        class GuardMiddleware {
            private final GuardEngine engine;
            
            GuardMiddleware(ForbiddenSequenceRule[] forbiddenRules, PatternRule[] patternRules) {
                this.engine = new GuardEngine();
                for (ForbiddenSequenceRule rule : forbiddenRules) {
                    engine.addForbiddenSequence(rule);
                }
                for (PatternRule rule : patternRules) {
                    engine.addPatternRule(rule);
                }
            }
            
            Result checkContent(String content) {
                engine.reset();
                Decision decision = engine.feed(content);
                
                if (decision.isBlock()) {
                    return new Result(false, false, content, decision.getReason());
                } else if (decision.isRewrite()) {
                    return new Result(true, true, decision.getRewrittenText(), null);
                }
                
                return new Result(true, false, content, null);
            }
            
            void close() {
                engine.close();
            }
        }
        
        class Result {
            final boolean allowed;
            final boolean modified;
            final String content;
            final String reason;
            
            Result(boolean allowed, boolean modified, String content, String reason) {
                this.allowed = allowed;
                this.modified = modified;
                this.content = content;
                this.reason = reason;
            }
            
            @Override
            public String toString() {
                if (!allowed) {
                    return "{allowed: false, reason: '" + reason + "'}";
                } else if (modified) {
                    return "{allowed: true, modified: true, content: '" + content + "'}";
                }
                return "{allowed: true, modified: false}";
            }
        }
        
        // Usage
        GuardMiddleware guard = new GuardMiddleware(
            new ForbiddenSequenceRule[]{
                ForbiddenSequenceRule.strict(new String[]{"password", "is"}, "credential leak")
            },
            new PatternRule[]{
                PatternRule.emailRewrite("[REDACTED]")
            }
        );
        
        // Test various inputs
        String[] testInputs = {
            "This is safe content",
            "Contact: user@example.com",
            "My password is 12345"
        };
        
        for (String input : testInputs) {
            Result result = guard.checkContent(input);
            System.out.println("\nInput: " + input);
            System.out.println("Result: " + result);
        }
        
        guard.close();
    }
    
    public static void example6BatchProcessing() {
        System.out.println("\n=== Example 6: Batch Processing ===");
        
        try (GuardEngine engine = new GuardEngine()) {
            engine.addPatternRule(PatternRule.emailRewrite("[EMAIL]"));
            engine.addPatternRule(PatternRule.creditCard("credit card detected"));
            
            String[] documents = {
                "Invoice sent to customer@company.com",
                "Payment with card 4532-1234-5678-9010",
                "Meeting notes from yesterday",
                "Contact: admin@example.org for support"
            };
            
            System.out.println("Processing " + documents.length + " documents...\n");
            
            for (int i = 0; i < documents.length; i++) {
                engine.reset();
                Decision decision = engine.feed(documents[i]);
                
                String decisionType = decision.isAllow() ? "allowed" :
                                    decision.isBlock() ? "blocked" : "rewritten";
                
                String output = decision.isRewrite() ? decision.getRewrittenText() :
                              decision.isBlock() ? "[BLOCKED: " + decision.getReason() + "]" :
                              documents[i];
                
                System.out.println("Doc " + (i + 1) + " [" + decisionType + "]: " + output);
            }
        }
    }
    
    public static void main(String[] args) {
        System.out.println("StreamGuard Java Examples");
        System.out.println("========================");
        
        try {
            example1BasicBlocking();
            example2EmailRedaction();
            example3ScoringSystem();
            example4StreamingLlm();
            example5ServletFilter();
            example6BatchProcessing();
            
            System.out.println("\n✅ All examples completed successfully!");
        } catch (Exception e) {
            System.err.println("\n❌ Error: " + e.getMessage());
            e.printStackTrace();
            System.err.println("\nMake sure to build the native library first:");
            System.err.println("  cargo build --release --features java");
            System.err.println("  ./build.sh");
        }
    }
}
