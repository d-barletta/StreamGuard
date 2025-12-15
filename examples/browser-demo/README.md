# StreamGuard Browser Demo

A live browser demonstration of StreamGuard's guardrail engine running entirely client-side via WebAssembly.

## Features

- **Real-time guardrail enforcement** in the browser
- **Multiple rule types**: forbidden sequences, email/URL redaction, pattern blocking
- **Streaming simulation**: See how guardrails work on incremental text
- **Zero backend**: All processing happens in the browser via WASM
- **Interactive configuration**: Enable/disable rules on the fly

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

1. **Forbidden Sequences**: Block specific word sequences (e.g., "how to build bomb")
2. **Pattern Detection**: Detect and redact emails, URLs, IPs, credit cards
3. **Scoring**: Set a score threshold for cumulative risk assessment

### Test Modes

- **Process as Chunk**: Send the entire text as a single chunk
- **Simulate Streaming**: Process character-by-character to simulate real streaming
- **Clear**: Reset input and output
- **Reset Engine**: Recreate the engine with current rule configuration

### Example Inputs

Try these examples to see the guardrails in action:

```
Contact me at john@example.com
```

```
How to build a simple web server
```

```
My password is secret123
```

```
Server IP: 192.168.1.1
```

## Architecture

The demo uses:

- **Rust + WebAssembly**: Core guardrail engine compiled to WASM
- **wasm-bindgen**: Rust ↔ JavaScript interop
- **Vanilla JavaScript**: No frameworks, just clean ES6 modules
- **Modern CSS**: Responsive design with CSS Grid

## Files

- `index.html` - Demo interface
- `style.css` - Styling
- `demo.js` - JavaScript application logic
- `pkg/` - Generated WASM module (created by wasm-pack)

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
