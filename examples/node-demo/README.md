# StreamGuard Node.js Examples

Server-side examples demonstrating how to use StreamGuard in a Node.js environment.

## Quick Start

### Build the Node.js Package

From the project root:

```bash
wasm-pack build --target nodejs --out-dir examples/node-demo/pkg-node
```

Or from this directory:

```bash
npm run build
```

### Run the Examples

```bash
cd examples/node
node index.js
```

Or use the npm script:

```bash
npm start
```

## Examples Included

### 1. Basic Forbidden Sequence Detection
Shows how to block specific word sequences like "how to build bomb".

### 2. Email Redaction
Demonstrates pattern-based redaction to protect sensitive data.

### 3. Scoring System
Shows cumulative risk scoring with thresholds for nuanced content moderation.

### 4. Streaming LLM Simulation
Simulates processing streaming LLM output with real-time guardrails.

### 5. Express Middleware Pattern
Template for integrating StreamGuard into Express.js applications.

### 6. Batch Processing
Example of processing multiple documents efficiently.

## Integration Patterns

### Express.js Server

```javascript
const express = require('express');
const { GuardEngine, PatternRule } = require('../../pkg-node/streamguard.js');

const app = express();
app.use(express.json());

// Create guardrail engine
const engine = new GuardEngine();
engine.add_rule(PatternRule.email_rewrite('[EMAIL]'));

app.post('/api/complete', (req, res) => {
    const { prompt } = req.body;
    
    // Check prompt through guardrails
    engine.reset();
    const decision = engine.feed(prompt);
    
    if (decision.is_block()) {
        return res.status(400).json({
            error: 'Content blocked',
            reason: decision.reason
        });
    }
    
    // Process with LLM...
    res.json({ result: 'success' });
});

app.listen(3000);
```

### Stream Processing

```javascript
const { Transform } = require('stream');
const { GuardEngine } = require('../../pkg-node/streamguard.js');

class GuardTransform extends Transform {
    constructor(engine) {
        super();
        this.engine = engine;
        this.stopped = false;
    }
    
    _transform(chunk, encoding, callback) {
        if (this.stopped) return callback();
        
        const text = chunk.toString();
        const decision = this.engine.feed(text);
        
        if (decision.is_block()) {
            this.stopped = true;
            this.emit('blocked', decision.reason);
            return callback();
        }
        
        if (decision.is_rewrite()) {
            this.push(decision.rewritten_text());
        } else {
            this.push(chunk);
        }
        
        callback();
    }
}

// Usage
const engine = new GuardEngine();
const guardStream = new GuardTransform(engine);

inputStream
    .pipe(guardStream)
    .pipe(outputStream);
```

### Worker Threads

```javascript
const { Worker } = require('worker_threads');

// worker.js
const { GuardEngine } = require('../../pkg-node/streamguard.js');
const { parentPort } = require('worker_threads');

const engine = new GuardEngine();
// Configure rules...

parentPort.on('message', (text) => {
    const decision = engine.feed(text);
    parentPort.postMessage(decision);
});

// main.js
const worker = new Worker('./worker.js');
worker.postMessage('text to check');
worker.on('message', (decision) => {
    console.log('Decision:', decision);
});
```

## Performance Considerations

### Reuse Engine Instances

```javascript
// ✅ Good: Reuse engine, reset between uses
const engine = new GuardEngine();
// Add rules once

function processText(text) {
    engine.reset();
    return engine.feed(text);
}

// ❌ Bad: Creating new engine each time
function processText(text) {
    const engine = new GuardEngine();
    // Add rules again...
    return engine.feed(text);
}
```

### Batch Processing

Process multiple items efficiently:

```javascript
const items = [...]; // Large array
const engine = new GuardEngine();

const results = items.map(item => {
    engine.reset();
    return engine.feed(item);
});
```

### Streaming

For long texts, process in chunks:

```javascript
const chunkSize = 1024;
for (let i = 0; i < longText.length; i += chunkSize) {
    const chunk = longText.substring(i, i + chunkSize);
    const decision = engine.feed(chunk);
    
    if (!decision.is_allow()) {
        break;
    }
}
```

## API Reference

See the main project [documentation](../../README.md) for the complete API reference.

## Requirements

- Node.js 14+
- wasm-pack (for building)

## License

Apache-2.0
