// StreamGuard Node.js TypeScript Example
// Demonstrates using StreamGuard with TypeScript for type-safe guardrails

// Use type-only import to avoid path resolution issues at compile time
// @ts-ignore - types exist at runtime from WASM package
const { WasmGuardEngine } = require('../pkg-node/streamguard');

// Type alias for convenience
type GuardEngine = typeof WasmGuardEngine.prototype;

interface ContentCheckResult {
    allowed: boolean;
    modified?: boolean;
    content?: string;
    reason?: string;
}

interface DocumentResult {
    index: number;
    original: string;
    decision: 'allowed' | 'blocked' | 'rewritten';
    output: string;
}

// Example 1: Basic forbidden sequence detection
function example1BasicBlocking(): void {
    console.log('\n=== Example 1: Basic Forbidden Sequence ===');
    
    const engine = new WasmGuardEngine();
    
    // Add a rule to block weapon-related instructions
    engine.addForbiddenSequence(
        ['how', 'to', 'build', 'bomb'],
        'forbidden weapons instructions'
    );
    
    // Test with benign text
    const safe = engine.feed('How to build a web application');
    console.log('Safe text:', safe);
    
    // Reset for next test
    engine.reset();
    
    // Test with forbidden sequence
    const chunks: string[] = ['How ', 'to ', 'build ', 'a ', 'bomb'];
    for (const chunk of chunks) {
        const decision = engine.feed(chunk);
        if (decision.decision === 'block') {
            console.log('🚫 Blocked:', decision.reason);
            break;
        }
    }
}

// Example 2: Email redaction
function example2EmailRedaction(): void {
    console.log('\n=== Example 2: Email Redaction ===');
    
    const engine = new WasmGuardEngine();
    
    // Add email redaction rule
    engine.addEmailRedaction('[EMAIL_REDACTED]');
    
    const text: string = 'Contact me at john@example.com for details';
    const decision = engine.feed(text);
    
    if (decision.decision === 'rewrite') {
        console.log('Original:', text);
        console.log('Redacted:', decision.rewritten_text);
    }
}

// Example 3: Multiple rules with scoring
function example3ScoringSystem(): void {
    console.log('\n=== Example 3: Scoring System ===');
    
    const engine = WasmGuardEngine.withScoreThreshold(100);
    
    // Add multiple rules
    engine.addForbiddenSequence(['password', 'is'], 'credential leak');
    engine.addForbiddenSequence(['secret', 'key'], 'secret exposure');
    
    console.log('Score threshold: 100');
    console.log('Processing chunks...');
    
    const chunks: string[] = [
        'The password is secret123',
        ' and the secret key is xyz'
    ];
    
    for (const chunk of chunks) {
        const decision = engine.feed(chunk);
        console.log(`Score: ${engine.currentScore()}`, decision);
        
        if (decision.decision === 'block') {
            console.log('🚫 Blocked due to score threshold!');
            break;
        }
    }
}

// Example 4: Streaming server simulation
function example4StreamingServer(): void {
    console.log('\n=== Example 4: Streaming LLM Simulation ===');
    
    const engine = new WasmGuardEngine();
    
    // Add various safety rules
    engine.addEmailRedaction('[EMAIL]');
    engine.addUrlRedaction('[URL]');
    engine.addForbiddenSequence(['how', 'to', 'hack'], 'security violation');
    
    // Simulate LLM streaming response
    const llmResponse: string = 'You can learn more at https://example.com or email me at admin@site.com';
    const chunkSize: number = 10;
    
    console.log('Original response:', llmResponse);
    console.log('Streaming with guardrails:');
    
    let output: string = '';
    for (let i = 0; i < llmResponse.length; i += chunkSize) {
        const chunk: string = llmResponse.substring(i, i + chunkSize);
        const decision = engine.feed(chunk);
        
        if (decision.decision === 'allow') {
            output += chunk;
            process.stdout.write(chunk);
        } else if (decision.decision === 'rewrite') {
            output = decision.rewritten_text || '';
            process.stdout.write('\n[Content rewritten]\n');
            console.log(output);
            break;
        } else if (decision.decision === 'block') {
            console.log('\n🚫 Stream blocked:', decision.reason);
            break;
        }
    }
    console.log();
}

// Example 5: Express.js middleware pattern with types
function example5ExpressMiddleware(): void {
    console.log('\n=== Example 5: Express Middleware Pattern ===');
    
    // Type-safe middleware factory
    function createGuardMiddleware(): { checkContent: (content: string) => ContentCheckResult } {
        const engine = new WasmGuardEngine();
        engine.addEmailRedaction('[REDACTED]');
        engine.addForbiddenSequence(['password', 'is'], 'credential leak');
        
        return {
            checkContent: (content: string): ContentCheckResult => {
                engine.reset();
                const decision = engine.feed(content);
                
                if (decision.decision === 'block') {
                    return {
                        allowed: false,
                        reason: decision.reason
                    };
                } else if (decision.decision === 'rewrite') {
                    return {
                        allowed: true,
                        modified: true,
                        content: decision.rewritten_text
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
    const guard = createGuardMiddleware();
    
    // Test various inputs
    const testInputs: string[] = [
        'This is safe content',
        'Contact: user@example.com',
        'My password is 12345'
    ];
    
    testInputs.forEach((input: string) => {
        const result: ContentCheckResult = guard.checkContent(input);
        console.log('\nInput:', input);
        console.log('Result:', result);
    });
}

// Example 6: Batch processing with type safety
function example6BatchProcessing(): void {
    console.log('\n=== Example 6: Batch Processing ===');
    
    const engine = new WasmGuardEngine();
    engine.addEmailRedaction('[EMAIL]');
    engine.addCreditCardBlocker('credit card detected');
    
    const documents: string[] = [
        'Invoice sent to customer@company.com',
        'Payment with card 4532-1234-5678-9010',
        'Meeting notes from yesterday',
        'Contact: admin@example.org for support'
    ];
    
    console.log('Processing', documents.length, 'documents...\n');
    
    const results: DocumentResult[] = documents.map((doc: string, index: number): DocumentResult => {
        engine.reset();
        const decision = engine.feed(doc);
        
        const decisionType: 'allowed' | 'blocked' | 'rewritten' = 
            decision.decision === 'allow' ? 'allowed' : 
            decision.decision === 'block' ? 'blocked' :
            'rewritten';
        
        const output: string = 
            decision.decision === 'rewrite' ? (decision.rewritten_text || doc) : 
            decision.decision === 'block' ? `[BLOCKED: ${decision.reason}]` : 
            doc;
        
        return {
            index,
            original: doc,
            decision: decisionType,
            output
        };
    });
    
    results.forEach((r: DocumentResult) => {
        console.log(`Doc ${r.index + 1} [${r.decision}]:`, r.output);
    });
}

// Example 7: Async generator pattern
async function* guardedStreamGenerator(
    chunks: string[],
    engine: GuardEngine
): AsyncGenerator<{ type: string; text?: string; reason?: string }, void, unknown> {
    for (const chunk of chunks) {
        const decision = engine.feed(chunk);
        
        if (decision.decision === 'block') {
            yield { type: 'block', reason: decision.reason };
            break;
        } else if (decision.decision === 'rewrite') {
            yield { type: 'rewrite', text: decision.rewritten_text };
            break;
        } else {
            yield { type: 'chunk', text: chunk };
        }
    }
}

async function example7AsyncGenerator(): Promise<void> {
    console.log('\n=== Example 7: Async Generator Pattern ===');
    
    const engine = new WasmGuardEngine();
    engine.addEmailRedaction('[EMAIL]');
    
    const chunks: string[] = ['Hello, ', 'contact ', 'me at ', 'admin@', 'example.', 'com'];
    
    console.log('Streaming chunks through async generator:');
    for await (const result of guardedStreamGenerator(chunks, engine)) {
        console.log('  ', result);
    }
}

// Run all examples
async function main(): Promise<void> {
    console.log('StreamGuard Node.js TypeScript Examples');
    console.log('========================================');
    
    try {
        example1BasicBlocking();
        example2EmailRedaction();
        example3ScoringSystem();
        example4StreamingServer();
        example5ExpressMiddleware();
        example6BatchProcessing();
        await example7AsyncGenerator();
        
        console.log('\n✅ All examples completed successfully!');
    } catch (error) {
        console.error('\n❌ Error:', (error as Error).message);
        console.error('\nMake sure to build the Node.js package first:');
        console.error('  npm run build');
        console.error('  npm run build:ts');
    }
}

main();
