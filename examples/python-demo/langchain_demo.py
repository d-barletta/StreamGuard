#!/usr/bin/env python3
"""
StreamGuard + LangChain Streaming Integration Examples

Demonstrates how to integrate StreamGuard guardrails with LangChain's
streaming capabilities for real-time content filtering.

Prerequisites:
    pip install langchain langchain-openai
    
Environment Variables:
    OPENAI_API_KEY: Your OpenAI API key (for real LLM examples)
"""

import sys
sys.path.insert(0, './pkg-python')

from streamguard import GuardEngine, ForbiddenSequenceRule, PatternRule

# LangChain imports (optional - examples gracefully handle missing dependencies)
try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.messages import HumanMessage
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.prompts import ChatPromptTemplate
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("⚠️  LangChain not installed. Install with: pip install langchain langchain-openai")
    print("   Running with simulated streaming instead.\n")


def simulate_streaming_response(text, chunk_size=5):
    """Simulate LLM streaming by yielding text chunks"""
    for i in range(0, len(text), chunk_size):
        yield text[i:i + chunk_size]


def example1_basic_streaming_with_guardrails():
    """Example 1: Basic streaming with content filtering"""
    print('\n=== Example 1: Basic LangChain-style Streaming with Guardrails ===')
    
    # Setup StreamGuard engine
    guard = GuardEngine()
    guard.add_forbidden_sequence(
        ForbiddenSequenceRule.with_gaps(
            ['how', 'to', 'hack'],
            'security violation'
        )
    )
    guard.add_pattern_rule(PatternRule.email_rewrite('[EMAIL_REDACTED]'))
    
    # Simulate LLM response
    llm_response = "You can learn more at the tutorial site or contact admin@example.com"
    
    print("Original (simulated) LLM response:")
    print(f"  {llm_response}\n")
    
    print("Streaming with guardrails:")
    output = ""
    blocked = False
    
    for chunk in simulate_streaming_response(llm_response, chunk_size=8):
        decision = guard.feed(chunk)
        
        if decision.is_allow():
            output += chunk
            print(chunk, end='', flush=True)
        elif decision.is_rewrite():
            output = decision.rewritten_text()
            print(f'\n[Rewritten: {output}]')
            break
        elif decision.is_block():
            print(f'\n🚫 Stream blocked: {decision.reason()}')
            blocked = True
            break
    
    if not blocked and not guard.feed('').is_rewrite():
        print(f'\n✓ Complete output: {output}')


def example2_callback_handler():
    """Example 2: Custom LangChain callback handler with StreamGuard"""
    print('\n=== Example 2: LangChain Callback Handler Integration ===')
    
    if not LANGCHAIN_AVAILABLE:
        print("Skipping - LangChain not installed\n")
        return
    
    class StreamGuardCallback(BaseCallbackHandler):
        """LangChain callback handler that applies guardrails in real-time"""
        
        def __init__(self, guard_engine):
            super().__init__()
            self.guard = guard_engine
            self.output_buffer = []
            self.blocked = False
            self.block_reason = None
            
        def on_llm_new_token(self, token: str, **kwargs):
            """Called when LLM generates a new token"""
            if self.blocked:
                return
            
            decision = self.guard.feed(token)
            
            if decision.is_allow():
                self.output_buffer.append(token)
                print(token, end='', flush=True)
            elif decision.is_rewrite():
                # Handle rewrite by replacing entire output
                rewritten = decision.rewritten_text()
                self.output_buffer = [rewritten]
                print(f'\n[Content rewritten]')
            elif decision.is_block():
                self.blocked = True
                self.block_reason = decision.reason()
                print(f'\n🚫 Stream blocked: {self.block_reason}')
                # In real scenario, you'd stop the LLM generation here
        
        def get_output(self):
            """Get the filtered output"""
            if self.blocked:
                return None, self.block_reason
            return ''.join(self.output_buffer), None
    
    # Setup guardrails
    guard = GuardEngine()
    guard.add_pattern_rule(PatternRule.email_rewrite('[REDACTED]'))
    
    # Create callback
    callback = StreamGuardCallback(guard)
    
    # Simulate token generation (in real scenario, this would be LLM)
    print("Simulating LLM token stream:")
    tokens = ["Hello", ", ", "contact", " ", "me", " ", "at", " ", 
              "john", "@", "example", ".", "com"]
    
    for token in tokens:
        callback.on_llm_new_token(token)
    
    output, reason = callback.get_output()
    print(f'\n\nFinal output: {output}')


def example3_streaming_chain_with_guardrails():
    """Example 3: LangChain streaming chain with guardrails"""
    print('\n=== Example 3: LangChain Chain with Streaming Guardrails ===')
    
    if not LANGCHAIN_AVAILABLE:
        print("Skipping - LangChain not installed\n")
        return
    
    def create_guarded_stream(llm_stream, guard_engine):
        """Generator that applies guardrails to LangChain stream"""
        for chunk in llm_stream:
            decision = guard_engine.feed(chunk)
            
            if decision.is_allow():
                yield chunk
            elif decision.is_rewrite():
                # Yield rewritten content and stop
                yield decision.rewritten_text()
                break
            elif decision.is_block():
                # Yield error and stop
                yield f"[BLOCKED: {decision.reason()}]"
                break
    
    # Setup guardrails
    guard = GuardEngine()
    guard.add_pattern_rule(PatternRule.url_rewrite('[LINK_REMOVED]'))
    guard.add_forbidden_sequence(
        ForbiddenSequenceRule.strict(
            ['password', 'is'],
            'credential exposure'
        )
    )
    
    # Simulate LLM streaming
    simulated_response = [
        "Check out ",
        "our website ",
        "at https://",
        "example.com ",
        "for more info"
    ]
    
    print("Original chunks: ", simulated_response)
    print("\nStreaming through guardrails:")
    
    output = ""
    for chunk in create_guarded_stream(simulated_response, guard):
        output += chunk
        print(chunk, end='', flush=True)
    
    print(f'\n\nFinal output: {output}')


def example4_rag_pipeline_with_guardrails():
    """Example 4: RAG pipeline with guardrails on retrieved content and output"""
    print('\n=== Example 4: RAG Pipeline with Dual Guardrails ===')
    
    # Guard for retrieved documents (block PII)
    doc_guard = GuardEngine()
    doc_guard.add_pattern_rule(PatternRule.email('PII in retrieved docs'))
    doc_guard.add_pattern_rule(PatternRule.credit_card('PII in retrieved docs'))
    
    # Guard for LLM output (rewrite PII)
    output_guard = GuardEngine()
    output_guard.add_pattern_rule(PatternRule.email_rewrite('[EMAIL]'))
    output_guard.add_pattern_rule(PatternRule.ipv4('IP address in output'))
    
    # Simulated retrieved documents
    documents = [
        "User guide for product setup",
        "Contact support at support@company.com",  # Should be caught
        "Installation instructions"
    ]
    
    print("1. Filtering retrieved documents:")
    safe_docs = []
    for doc in documents:
        doc_guard.reset()
        decision = doc_guard.feed(doc)
        
        if decision.is_allow():
            safe_docs.append(doc)
            print(f"  ✓ {doc}")
        else:
            print(f"  ✗ Blocked: {doc} (reason: {decision.reason()})")
    
    # Simulated LLM response using safe documents
    llm_response = "Based on the docs, contact admin@company.com or visit 192.168.1.1"
    
    print(f"\n2. Original LLM response:")
    print(f"  {llm_response}")
    
    print("\n3. Streaming LLM output through guardrails:")
    final_output = ""
    
    for chunk in simulate_streaming_response(llm_response, chunk_size=10):
        decision = output_guard.feed(chunk)
        
        if decision.is_allow():
            final_output += chunk
            print(chunk, end='', flush=True)
        elif decision.is_rewrite():
            final_output = decision.rewritten_text()
            print(f'\n[Rewritten]')
            break
        elif decision.is_block():
            print(f'\n🚫 Blocked: {decision.reason()}')
            break
    
    print(f'\n\n✓ Safe output: {final_output}')


def example5_multi_rule_scoring():
    """Example 5: Multiple guardrails with risk scoring"""
    print('\n=== Example 5: LangChain Streaming with Risk Scoring ===')
    
    # Setup engine with scoring threshold
    guard = GuardEngine.with_score_threshold(100)
    
    # Add multiple rules with different risk scores
    guard.add_forbidden_sequence(
        ForbiddenSequenceRule.with_score(
            ['credit', 'card'],
            'financial info',
            40
        )
    )
    guard.add_forbidden_sequence(
        ForbiddenSequenceRule.with_score(
            ['social', 'security'],
            'PII',
            60
        )
    )
    guard.add_forbidden_sequence(
        ForbiddenSequenceRule.with_score(
            ['password', 'is'],
            'credential leak',
            50
        )
    )
    
    # Simulated LLM response with multiple violations
    response = "Your credit card number and social security should be kept safe"
    
    print(f"Response: {response}")
    print(f"Score threshold: 100\n")
    print("Processing stream:")
    
    output = ""
    decision = None
    for chunk in simulate_streaming_response(response, chunk_size=12):
        decision = guard.feed(chunk)
        score = guard.current_score()
        
        print(f"  Chunk: '{chunk}' → Score: {score}")
        
        if decision.is_block():
            print(f"🚫 Blocked at score {score}: {decision.reason()}")
            break
        
        output += chunk
    
    if decision and not decision.is_block():
        print(f"✓ Allowed with score {guard.current_score()}")


def example6_real_openai_integration():
    """Example 6: Real OpenAI streaming with guardrails (requires API key)"""
    print('\n=== Example 6: Real OpenAI Integration (requires API key) ===')
    
    try:
        from langchain_openai import ChatOpenAI
        import os
        
        if 'OPENAI_API_KEY' not in os.environ:
            print("⚠️  OPENAI_API_KEY not set. Skipping real API call.")
            print("   Set your API key to try this example:")
            print("   export OPENAI_API_KEY='your-key-here'\n")
            return
        
        # Setup guardrails
        guard = GuardEngine()
        guard.add_pattern_rule(PatternRule.email_rewrite('[EMAIL_REDACTED]'))
        
        # Create LLM
        llm = ChatOpenAI(
            model="gpt-3.5-turbo",
            temperature=0.7,
            streaming=True
        )
        
        # Create prompt
        prompt = "Write a short welcome message that includes an example email address."
        
        print(f"Prompt: {prompt}\n")
        print("Streaming response with guardrails:")
        
        output = ""
        for chunk in llm.stream(prompt):
            content = chunk.content if hasattr(chunk, 'content') else str(chunk)
            
            decision = guard.feed(content)
            
            if decision.is_allow():
                output += content
                print(content, end='', flush=True)
            elif decision.is_rewrite():
                output = decision.rewritten_text()
                print(f'\n[Rewritten: {output}]')
                break
            elif decision.is_block():
                print(f'\n🚫 Blocked: {decision.reason()}')
                break
        
        print(f'\n\nFinal output: {output}')
        
    except ImportError:
        print("⚠️  langchain-openai not installed.")
        print("   Install with: pip install langchain-openai\n")
    except Exception as e:
        print(f"❌ Error: {e}\n")


def example7_async_streaming():
    """Example 7: Async streaming pattern (conceptual)"""
    print('\n=== Example 7: Async Streaming Pattern (Conceptual) ===')
    
    print("""
This example demonstrates the pattern for async/await integration:

```python
import asyncio
from langchain_openai import ChatOpenAI
from streamguard import GuardEngine, PatternRule

async def guarded_async_stream(llm, prompt, guard):
    async for chunk in llm.astream(prompt):
        decision = guard.feed(chunk.content)
        
        if decision.is_allow():
            yield chunk.content
        elif decision.is_rewrite():
            yield decision.rewritten_text()
            break
        elif decision.is_block():
            yield f"[BLOCKED: {decision.reason()}]"
            break

async def main():
    guard = GuardEngine()
    guard.add_pattern_rule(PatternRule.email_rewrite('[EMAIL]'))
    
    llm = ChatOpenAI(streaming=True)
    
    async for chunk in guarded_async_stream(llm, "Hello!", guard):
        print(chunk, end='', flush=True)

# Run with: asyncio.run(main())
```

Key points:
- StreamGuard is synchronous (deterministic, zero-copy)
- Easily wraps in async generators
- No blocking operations in guardrail checks
- Suitable for FastAPI, async LangChain chains
""")


# Main execution
if __name__ == '__main__':
    print('StreamGuard + LangChain Integration Examples')
    print('=' * 50)
    
    try:
        example1_basic_streaming_with_guardrails()
        example2_callback_handler()
        example3_streaming_chain_with_guardrails()
        example4_rag_pipeline_with_guardrails()
        example5_multi_rule_scoring()
        example6_real_openai_integration()
        example7_async_streaming()
        
        print('\n' + '=' * 50)
        print('✅ All examples completed!')
        print('\nTo use with real LangChain + OpenAI:')
        print('  1. pip install langchain langchain-openai')
        print('  2. export OPENAI_API_KEY="your-key"')
        print('  3. python langchain_demo.py')
        
    except Exception as e:
        print(f'\n❌ Error: {e}')
        import traceback
        traceback.print_exc()
        print('\nMake sure to build the Python extension first:')
        print('  pip install maturin')
        print('  maturin develop --release')
