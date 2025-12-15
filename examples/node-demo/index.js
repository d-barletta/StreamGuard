// StreamGuard Node.js Example
// Demonstrates using StreamGuard for server-side guardrails

const { GuardEngine } = require('./pkg-node/streamguard.js');
const { ForbiddenSequenceRule, PatternRule } = require('./pkg-node/streamguard.js');

// Example 1: Basic forbidden sequence detection
function example1_basicBlocking() {
    console.log('\n=== Example 1: Basic Forbidden Sequence ===');
    
    const engine = new GuardEngine();
    
    // Add a rule to block weapon-related instructions
    const rule = ForbiddenSequenceRule.with_gaps(
        ['how', 'to', 'build', 'bomb'],
        'forbidden weapons instructions'
    );
    engine.add_rule(rule);
    
    // Test with benign text
    const safe = engine.feed('How to build a web application');
    console.log('Safe text:', safe);
    
    // Reset for next test
    engine.reset();
    
    // Test with forbidden sequence
    const chunks = ['How ', 'to ', 'build ', 'a ', 'bomb'];
    for (const chunk of chunks) {
        const decision = engine.feed(chunk);
        if (decision.is_block()) {
            console.log('🚫 Blocked:', decision.reason);
            break;
        }
    }
}

// Example 2: Email redaction
function example2_emailRedaction() {
    console.log('\n=== Example 2: Email Redaction ===');
    
    const engine = new GuardEngine();
    
    // Add email redaction rule
    const emailRule = PatternRule.email_rewrite('[EMAIL_REDACTED]');
    engine.add_rule(emailRule);
    
    const text = 'Contact me at john@example.com for details';
    const decision = engine.feed(text);
    
    if (decision.is_rewrite()) {
        console.log('Original:', text);
        console.log('Redacted:', decision.rewritten_text());
    }
}

// Example 3: Multiple rules with scoring
function example3_scoringSystem() {
    console.log('\n=== Example 3: Scoring System ===');
    
    const engine = GuardEngine.with_score_threshold(100);
    
    // Add multiple rules with scores
    const rule1 = ForbiddenSequenceRule.new_with_score(
        ['password', 'is'],
        'credential leak',
        50
    );
    const rule2 = ForbiddenSequenceRule.new_with_score(
        ['secret', 'key'],
        'secret exposure',
        50
    );
    
    engine.add_rule(rule1);
    engine.add_rule(rule2);
    
    console.log('Score threshold:', 100);
    console.log('Processing chunks...');
    
    const chunks = [
        'The password is secret123',
        ' and the secret key is xyz'
    ];
    
    for (const chunk of chunks) {
        const decision = engine.feed(chunk);
        console.log(`Score: ${engine.current_score()}`, decision);
        
        if (decision.is_block()) {
            console.log('🚫 Blocked due to score threshold!');
            break;
        }
    }
}

// Example 4: Streaming server simulation
function example4_streamingServer() {
    console.log('\n=== Example 4: Streaming LLM Simulation ===');
    
    const engine = new GuardEngine();
    
    // Add various safety rules
    engine.add_rule(PatternRule.email_rewrite('[EMAIL]'));
    engine.add_rule(PatternRule.url_rewrite('[URL]'));
    engine.add_rule(ForbiddenSequenceRule.with_gaps(
        ['how', 'to', 'hack'],
        'security violation'
    ));
    
    // Simulate LLM streaming response
    const llmResponse = 'You can learn more at https://example.com or email me at admin@site.com';
    const chunkSize = 10;
    
    console.log('Original response:', llmResponse);
    console.log('Streaming with guardrails:');
    
    let output = '';
    for (let i = 0; i < llmResponse.length; i += chunkSize) {
        const chunk = llmResponse.substring(i, i + chunkSize);
        const decision = engine.feed(chunk);
        
        if (decision.is_allow()) {
            output += chunk;
            process.stdout.write(chunk);
        } else if (decision.is_rewrite()) {
            output = decision.rewritten_text();
            process.stdout.write('\n[Content rewritten]\n');
            console.log(output);
            break;
        } else if (decision.is_block()) {
            console.log('\n🚫 Stream blocked:', decision.reason);
            break;
        }
    }
    console.log();
}

// Example 5: Express.js middleware pattern
function example5_expressMiddleware() {
    console.log('\n=== Example 5: Express Middleware Pattern ===');
    
    // Middleware factory
    function createGuardMiddleware(rules) {
        const engine = new GuardEngine();
        rules.forEach(rule => engine.add_rule(rule));
        
        return {
            checkContent: (content) => {
                engine.reset();
                const decision = engine.feed(content);
                
                if (decision.is_block()) {
                    return {
                        allowed: false,
                        reason: decision.reason
                    };
                } else if (decision.is_rewrite()) {
                    return {
                        allowed: true,
                        modified: true,
                        content: decision.rewritten_text()
                    };
                }
                
                return {
                    allowed: true,
                    modified: false,
                    content
                };
            }
        };
    }
    
    // Usage
    const guard = createGuardMiddleware([
        PatternRule.email_rewrite('[REDACTED]'),
        ForbiddenSequenceRule.strict(['password', 'is'], 'credential leak')
    ]);
    
    // Test various inputs
    const testInputs = [
        'This is safe content',
        'Contact: user@example.com',
        'My password is 12345'
    ];
    
    testInputs.forEach(input => {
        const result = guard.checkContent(input);
        console.log('\nInput:', input);
        console.log('Result:', result);
    });
}

// Example 6: Batch processing
function example6_batchProcessing() {
    console.log('\n=== Example 6: Batch Processing ===');
    
    const engine = new GuardEngine();
    engine.add_rule(PatternRule.email_rewrite('[EMAIL]'));
    engine.add_rule(PatternRule.credit_card('credit card detected'));
    
    const documents = [
        'Invoice sent to customer@company.com',
        'Payment with card 4532-1234-5678-9010',
        'Meeting notes from yesterday',
        'Contact: admin@example.org for support'
    ];
    
    console.log('Processing', documents.length, 'documents...\n');
    
    const results = documents.map((doc, index) => {
        engine.reset();
        const decision = engine.feed(doc);
        
        return {
            index,
            original: doc,
            decision: decision.is_allow() ? 'allowed' : 
                     decision.is_block() ? 'blocked' :
                     'rewritten',
            output: decision.is_rewrite() ? decision.rewritten_text() : 
                   decision.is_block() ? `[BLOCKED: ${decision.reason}]` : doc
        };
    });
    
    results.forEach(r => {
        console.log(`Doc ${r.index + 1} [${r.decision}]:`, r.output);
    });
}

// Run all examples
console.log('StreamGuard Node.js Examples');
console.log('============================');

try {
    example1_basicBlocking();
    example2_emailRedaction();
    example3_scoringSystem();
    example4_streamingServer();
    example5_expressMiddleware();
    example6_batchProcessing();
    
    console.log('\n✅ All examples completed successfully!');
} catch (error) {
    console.error('\n❌ Error:', error.message);
    console.error('\nMake sure to build the Node.js package first:');
    console.error('  wasm-pack build --target nodejs --out-dir pkg-node');
}
