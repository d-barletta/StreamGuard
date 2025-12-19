# StreamGuard Browser Demo

A live browser demonstration of StreamGuard's guardrail engine running entirely client-side via WebAssembly.

## Features

- **Real-time guardrail enforcement** in the browser
- **Multiple rule types**: forbidden sequences, email/URL redaction, pattern blocking
- **Complex DFA patterns**: Multi-token sequence detection with gap tolerance
- **Jailbreak detection**: Real-world prompt injection and instruction override patterns
- **Streaming simulation**: See how guardrails work on incremental text
- **Zero backend**: All processing happens in the browser via WASM
- **Interactive configuration**: Enable/disable rules on the fly
- **Pre-configured examples**: From simple redaction to advanced security patterns

## Quick Start

### Prerequisites

- Rust toolchain (install from [rustup.rs](https://rustup.rs/))
- wasm-pack: `cargo install wasm-pack`
- A local web server (e.g., Python's http.server, Node's http-server, or VS Code's Live Server)

### Build the WASM Module

From the project root directory:

```bash
# Build the WASM module
wasm-pack build --target web --out-dir examples/browser-demo/pkg

# Or use the npm script if package.json is set up:
# npm run build:wasm
```

### Run the Demo

Start a local web server in the `examples/browser-demo` directory:

```bash
cd examples/browser-demo

# Option 1: Python
python3 -m http.server 8080

# Option 2: Node.js (requires http-server: npm install -g http-server)
http-server -p 8080

# Option 3: VS Code Live Server extension
# Right-click index.html and select "Open with Live Server"
```

Open your browser to http://localhost:8080

## Usage

### Configure Rules

1. **Redaction (Rewrite)**: Replace sensitive patterns with placeholders
   - Email addresses
   - URLs
   - IPv4 addresses
   - Credit card numbers

2. **Forbidden Sequences (Block)**: Stop the stream on dangerous patterns
   - Simple sequences: "how to build bomb"
   - Credential leaks: "password is"
   - **DAN jailbreak**: "ignore previous instructions" (multi-token DFA)
   - **Admin override**: "ignore" → "instructions" → "admin" (with gaps)

3. **Scoring**: Cumulative risk threshold (optional)

### Test Modes

- **Process as Chunk**: Send the entire text as a single chunk
- **Simulate Streaming**: Process character-by-character to simulate real streaming
- **Clear**: Reset input and output
- **Reset Engine**: Recreate the engine with current rule configuration

### Example Scenarios

The demo includes several pre-configured examples accessible via the dropdown menu:

#### **Basic (Redaction)**
- Tests email, URL, IP address, and credit card redaction
- Shows simple pattern matching in action

#### **Security Block**
- Demonstrates blocking forbidden sequences like "how to build bomb"
- Tests credential leak detection ("password is")

#### **Jailbreak Detection**  
- Complex DFA pattern: detects "ignore previous instructions"
- Multi-token sequence matching with deterministic state machine
- Real-world security scenario

#### **Complex DFA Patterns**
- Advanced pattern: "ignore" → "instructions" → "admin" (with gaps)
- Tests instruction override and privilege escalation attempts
- Demonstrates streaming DFA capabilities

#### **Streaming Edge Cases**
- Tests pattern detection across chunk boundaries
- Multiple PII types in rapid succession
- Verifies deterministic streaming behavior

## Architecture

The demo uses:

- **Rust + WebAssembly**: Core guardrail engine compiled to WASM
- **wasm-bindgen**: Rust ↔ JavaScript interop
- **Vanilla JavaScript**: No frameworks, just clean ES6 modules
- **Modern CSS**: Responsive design with CSS Grid

## Files

- `index.html` - Demo interface with rule configuration
- `style.css` - Styling with visual feedback
- `demo.js` - JavaScript application logic
- `pkg/` - Generated WASM module (created by wasm-pack)
- `EXAMPLES.md` - Detailed guide to complex patterns and DFA examples
- `README.md` - This file

## Learn More

For detailed explanations of the complex DFA patterns, jailbreak detection, and technical architecture, see **[EXAMPLES.md](EXAMPLES.md)**.

Topics covered:
- Multi-token sequence matching
- DFA state machines
- Streaming edge cases
- Comparison with regex and LLM-based approaches
- Performance characteristics

## Development

To make changes:

1. Modify the Rust code in `src/`
2. Rebuild with `wasm-pack build --target web --out-dir examples/browser-demo/pkg`
3. Refresh the browser

The WASM bindings are defined in `src/wasm.rs`.

## Performance

The WASM engine provides:

- **Near-native performance**: Compiled Rust code
- **No network latency**: All processing is local
- **Deterministic behavior**: Same input → same output
- **O(n) complexity**: Linear time processing

## Browser Compatibility

Requires a modern browser with WebAssembly support:

- Chrome/Edge 57+
- Firefox 52+
- Safari 11+

## License

Apache-2.0
