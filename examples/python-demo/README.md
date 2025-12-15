# StreamGuard Python Examples

Native Python bindings for StreamGuard using PyO3. Zero-copy performance with native Rust speed.

## Quick Start

### Prerequisites

- Python 3.7+ (3.9+ recommended)
- Rust toolchain
- pip

### Build the Python Extension

From this directory:

```bash
# Install maturin
python3 -m pip install --user maturin

# Build and install in development mode
maturin develop --release --features python
```

Or use the build script:

```bash
./build.sh
```

### Run Examples

```bash
python demo.py
```

## Examples Included

### 1. Basic Forbidden Sequence Detection
Demonstrates blocking harmful content patterns incrementally.

### 2. Email Redaction
Shows pattern-based PII redaction with rewrite rules.

### 3. Scoring System
Multiple rules with cumulative risk scoring and thresholds.

### 4. Streaming LLM Simulation
Chunk-by-chunk processing of LLM outputs with inline guardrails.

### 5. Flask Middleware Pattern
Reusable middleware class for web framework integration.

### 6. Batch Processing
Efficient processing of multiple documents with engine reuse.

### 7. Generator Pattern
Python generator-based streaming with guardrails.

## Integration Patterns

### Flask Application

```python
from flask import Flask, request, jsonify
from streamguard import GuardEngine, PatternRule

app = Flask(__name__)
guard = GuardEngine()
guard.add_pattern_rule(PatternRule.email_rewrite('[REDACTED]'))

@app.route('/generate', methods=['POST'])
def generate():
    guard.reset()
    text = request.json['text']
    decision = guard.feed(text)
    
    if decision.is_block():
        return jsonify({'error': decision.reason()}), 403
    elif decision.is_rewrite():
        return jsonify({'text': decision.rewritten_text()})
    else:
        return jsonify({'text': text})
```

### Streaming with Generators

```python
def stream_with_guards(chunks):
    engine = GuardEngine()
    engine.add_pattern_rule(PatternRule.email_rewrite('[EMAIL]'))
    
    for chunk in chunks:
        decision = engine.feed(chunk)
        if decision.is_allow():
            yield chunk
        elif decision.is_rewrite():
            yield decision.rewritten_text()
            break
        else:
            break
```

### FastAPI Integration

```python
from fastapi import FastAPI
from streamguard import GuardEngine, ForbiddenSequenceRule

app = FastAPI()
guard = GuardEngine()

@app.post("/check")
async def check_content(text: str):
    guard.reset()
    decision = guard.feed(text)
    return {
        "allowed": decision.is_allow(),
        "blocked": decision.is_block(),
        "reason": decision.reason() if decision.is_block() else None
    }
```

## Performance Tips

1. **Reuse Engine Instances**: Create one engine and reset between uses
2. **Batch Processing**: Process multiple items with the same engine
3. **Native Performance**: PyO3 bindings have minimal overhead
4. **Zero-Copy**: Text processing happens in Rust without copying

## API Reference

### GuardEngine

- `GuardEngine()` - Create new engine
- `GuardEngine.with_score_threshold(threshold)` - Create with scoring
- `.add_forbidden_sequence(rule)` - Add sequence rule
- `.add_pattern_rule(rule)` - Add pattern rule
- `.feed(chunk)` - Process text chunk
- `.reset()` - Reset state
- `.current_score()` - Get current score

### ForbiddenSequenceRule

- `ForbiddenSequenceRule.strict(tokens, reason)` - Strict sequence
- `ForbiddenSequenceRule.with_gaps(tokens, reason)` - Allow gaps
- `ForbiddenSequenceRule.with_score(tokens, reason, score)` - With scoring

### PatternRule

- `PatternRule.email(reason)` - Block emails
- `PatternRule.email_rewrite(replacement)` - Redact emails
- `PatternRule.url(reason)` - Block URLs
- `PatternRule.url_rewrite(replacement)` - Redact URLs
- `PatternRule.ipv4(reason)` - Block IPv4 addresses
- `PatternRule.credit_card(reason)` - Block credit cards

### Decision

- `.is_allow()` - Check if allowed
- `.is_block()` - Check if blocked
- `.is_rewrite()` - Check if rewritten
- `.reason()` - Get block reason (if blocked)
- `.rewritten_text()` - Get rewritten text (if rewritten)

## Building from Source

### Development Build

```bash
maturin develop
```

### Release Build

```bash
maturin develop --release
```

### Build Wheel

```bash
maturin build --release
```

## System Requirements

- Python 3.7+
- Rust toolchain (for building)
- maturin (for building)

## Notes

- Native Rust performance (no WASM overhead)
- Zero external dependencies in runtime
- Thread-safe (each engine instance is independent)
- Compatible with all Python web frameworks
