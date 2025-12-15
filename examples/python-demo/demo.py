#!/usr/bin/env python3
"""
StreamGuard Python Examples
Demonstrates using StreamGuard native Python bindings for server-side guardrails
"""

import sys
sys.path.insert(0, './pkg-python')

from streamguard import GuardEngine, ForbiddenSequenceRule, PatternRule


def example1_basic_blocking():
    """Example 1: Basic forbidden sequence detection"""
    print('\n=== Example 1: Basic Forbidden Sequence ===')
    
    engine = GuardEngine()
    
    # Add a rule to block weapon-related instructions
    rule = ForbiddenSequenceRule.with_gaps(
        ['how', 'to', 'build', 'bomb'],
        'forbidden weapons instructions'
    )
    engine.add_forbidden_sequence(rule)
    
    # Test with benign text
    safe = engine.feed('How to build a web application')
    print(f'Safe text: {safe}')
    
    # Reset for next test
    engine.reset()
    
    # Test with forbidden sequence
    chunks = ['How ', 'to ', 'build ', 'a ', 'bomb']
    for chunk in chunks:
        decision = engine.feed(chunk)
        if decision.is_block():
            print(f'🚫 Blocked: {decision.reason()}')
            break


def example2_email_redaction():
    """Example 2: Email redaction"""
    print('\n=== Example 2: Email Redaction ===')
    
    engine = GuardEngine()
    
    # Add email redaction rule
    email_rule = PatternRule.email_rewrite('[EMAIL_REDACTED]')
    engine.add_pattern_rule(email_rule)
    
    text = 'Contact me at john@example.com for details'
    decision = engine.feed(text)
    
    if decision.is_rewrite():
        print(f'Original: {text}')
        print(f'Redacted: {decision.rewritten_text()}')


def example3_scoring_system():
    """Example 3: Multiple rules with scoring"""
    print('\n=== Example 3: Scoring System ===')
    
    engine = GuardEngine.with_score_threshold(100)
    
    # Add multiple rules with scores
    rule1 = ForbiddenSequenceRule.with_score(
        ['password', 'is'],
        'credential leak',
        50
    )
    rule2 = ForbiddenSequenceRule.with_score(
        ['secret', 'key'],
        'secret exposure',
        50
    )
    
    engine.add_forbidden_sequence(rule1)
    engine.add_forbidden_sequence(rule2)
    
    print('Score threshold: 100')
    print('Processing chunks...')
    
    chunks = [
        'The password is secret123',
        ' and the secret key is xyz'
    ]
    
    for chunk in chunks:
        decision = engine.feed(chunk)
        print(f'Score: {engine.current_score()}', decision)
        
        if decision.is_block():
            print('🚫 Blocked due to score threshold!')
            break


def example4_streaming_llm():
    """Example 4: Streaming LLM simulation"""
    print('\n=== Example 4: Streaming LLM Simulation ===')
    
    engine = GuardEngine()
    
    # Add various safety rules
    engine.add_pattern_rule(PatternRule.email_rewrite('[EMAIL]'))
    engine.add_pattern_rule(PatternRule.url_rewrite('[URL]'))
    engine.add_forbidden_sequence(
        ForbiddenSequenceRule.with_gaps(
            ['how', 'to', 'hack'],
            'security violation'
        )
    )
    
    # Simulate LLM streaming response
    llm_response = 'You can learn more at https://example.com or email me at admin@site.com'
    chunk_size = 10
    
    print(f'Original response: {llm_response}')
    print('Streaming with guardrails:')
    
    output = ''
    for i in range(0, len(llm_response), chunk_size):
        chunk = llm_response[i:i + chunk_size]
        decision = engine.feed(chunk)
        
        if decision.is_allow():
            output += chunk
            print(chunk, end='', flush=True)
        elif decision.is_rewrite():
            output = decision.rewritten_text()
            print('\n[Content rewritten]')
            print(output)
            break
        elif decision.is_block():
            print(f'\n🚫 Stream blocked: {decision.reason()}')
            break
    print()


def example5_flask_middleware():
    """Example 5: Flask middleware pattern"""
    print('\n=== Example 5: Flask Middleware Pattern ===')
    
    # Middleware factory
    class GuardMiddleware:
        def __init__(self, rules):
            self.engine = GuardEngine()
            for rule in rules:
                if isinstance(rule, ForbiddenSequenceRule):
                    self.engine.add_forbidden_sequence(rule)
                elif isinstance(rule, PatternRule):
                    self.engine.add_pattern_rule(rule)
        
        def check_content(self, content):
            self.engine.reset()
            decision = self.engine.feed(content)
            
            if decision.is_block():
                return {
                    'allowed': False,
                    'reason': decision.reason()
                }
            elif decision.is_rewrite():
                return {
                    'allowed': True,
                    'modified': True,
                    'content': decision.rewritten_text()
                }
            
            return {
                'allowed': True,
                'modified': False,
                'content': content
            }
    
    # Usage
    guard = GuardMiddleware([
        PatternRule.email_rewrite('[REDACTED]'),
        ForbiddenSequenceRule.strict(['password', 'is'], 'credential leak')
    ])
    
    # Test various inputs
    test_inputs = [
        'This is safe content',
        'Contact: user@example.com',
        'My password is 12345'
    ]
    
    for input_text in test_inputs:
        result = guard.check_content(input_text)
        print(f'\nInput: {input_text}')
        print(f'Result: {result}')


def example6_batch_processing():
    """Example 6: Batch processing"""
    print('\n=== Example 6: Batch Processing ===')
    
    engine = GuardEngine()
    engine.add_pattern_rule(PatternRule.email_rewrite('[EMAIL]'))
    engine.add_pattern_rule(PatternRule.credit_card('credit card detected'))
    
    documents = [
        'Invoice sent to customer@company.com',
        'Payment with card 4532-1234-5678-9010',
        'Meeting notes from yesterday',
        'Contact: admin@example.org for support'
    ]
    
    print(f'Processing {len(documents)} documents...\n')
    
    results = []
    for index, doc in enumerate(documents):
        engine.reset()
        decision = engine.feed(doc)
        
        decision_type = 'allowed' if decision.is_allow() else \
                       'blocked' if decision.is_block() else \
                       'rewritten'
        
        output = decision.rewritten_text() if decision.is_rewrite() else \
                f'[BLOCKED: {decision.reason()}]' if decision.is_block() else \
                doc
        
        results.append({
            'index': index,
            'original': doc,
            'decision': decision_type,
            'output': output
        })
    
    for r in results:
        print(f"Doc {r['index'] + 1} [{r['decision']}]: {r['output']}")


def example7_async_generator():
    """Example 7: Python generator for streaming"""
    print('\n=== Example 7: Generator Pattern ===')
    
    def guarded_stream(chunks, engine):
        """Generator that applies guardrails to stream chunks"""
        for chunk in chunks:
            decision = engine.feed(chunk)
            
            if decision.is_block():
                yield {'type': 'block', 'reason': decision.reason()}
                break
            elif decision.is_rewrite():
                yield {'type': 'rewrite', 'text': decision.rewritten_text()}
                break
            else:
                yield {'type': 'chunk', 'text': chunk}
    
    engine = GuardEngine()
    engine.add_pattern_rule(PatternRule.email_rewrite('[EMAIL]'))
    
    chunks = ['Hello, ', 'contact ', 'me at ', 'admin@', 'example.', 'com']
    
    print('Streaming chunks through generator:')
    for result in guarded_stream(chunks, engine):
        print(f'  {result}')


# Run all examples
if __name__ == '__main__':
    print('StreamGuard Python Examples')
    print('============================')
    
    try:
        example1_basic_blocking()
        example2_email_redaction()
        example3_scoring_system()
        example4_streaming_llm()
        example5_flask_middleware()
        example6_batch_processing()
        example7_async_generator()
        
        print('\n✅ All examples completed successfully!')
    except Exception as e:
        print(f'\n❌ Error: {e}')
        print('\nMake sure to build the Python extension first:')
        print('  pip install maturin')
        print('  maturin develop --release')
