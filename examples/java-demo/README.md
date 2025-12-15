# StreamGuard Java Examples

Native Java JNI bindings for StreamGuard. Zero-copy performance with native Rust speed.

## Quick Start

### Prerequisites

- Java 8+ (JDK required for building)
- Maven 3.6+
- Rust toolchain

### Build and Run

From this directory:

```bash
./build.sh
```

Or manually:

```bash
# Build native library
cd ../..
cargo build --release --features java

# Compile and run Java code
cd examples/java-demo
mvn clean compile
mvn exec:java -Djava.library.path=../../target/release
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

### 5. Servlet Filter Pattern
Reusable middleware class for Java web framework integration.

### 6. Batch Processing
Efficient processing of multiple documents with engine reuse.

## Integration Patterns

### Spring Boot REST Controller

```java
import com.streamguard.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class GuardrailController {
    private final GuardEngine engine;
    
    public GuardrailController() {
        this.engine = new GuardEngine();
        this.engine.addPatternRule(PatternRule.emailRewrite("[REDACTED]"));
    }
    
    @PostMapping("/check")
    public Map<String, Object> checkContent(@RequestBody String text) {
        engine.reset();
        Decision decision = engine.feed(text);
        
        Map<String, Object> result = new HashMap<>();
        result.put("allowed", decision.isAllow());
        result.put("blocked", decision.isBlock());
        if (decision.isBlock()) {
            result.put("reason", decision.getReason());
        }
        if (decision.isRewrite()) {
            result.put("content", decision.getRewrittenText());
        }
        return result;
    }
}
```

### Servlet Filter

```java
import com.streamguard.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;

public class GuardFilter implements Filter {
    private GuardEngine engine;
    
    @Override
    public void init(FilterConfig config) {
        engine = new GuardEngine();
        engine.addPatternRule(PatternRule.emailRewrite("[EMAIL]"));
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        
        // Wrap request to capture body
        ContentCachingRequestWrapper wrapper = new ContentCachingRequestWrapper(req);
        String content = new String(wrapper.getContentAsByteArray());
        
        engine.reset();
        Decision decision = engine.feed(content);
        
        if (decision.isBlock()) {
            ((HttpServletResponse) response).sendError(403, decision.getReason());
            return;
        }
        
        chain.doFilter(wrapper, response);
    }
    
    @Override
    public void destroy() {
        if (engine != null) {
            engine.close();
        }
    }
}
```

### Streaming with CompletableFuture

```java
import com.streamguard.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;

public class StreamGuardAsync {
    public static CompletableFuture<String> processStream(Stream<String> chunks) {
        return CompletableFuture.supplyAsync(() -> {
            try (GuardEngine engine = new GuardEngine()) {
                engine.addPatternRule(PatternRule.emailRewrite("[EMAIL]"));
                
                StringBuilder result = new StringBuilder();
                for (String chunk : chunks.toArray(String[]::new)) {
                    Decision decision = engine.feed(chunk);
                    
                    if (decision.isAllow()) {
                        result.append(chunk);
                    } else if (decision.isRewrite()) {
                        return decision.getRewrittenText();
                    } else {
                        throw new SecurityException(decision.getReason());
                    }
                }
                return result.toString();
            }
        });
    }
}
```

## Performance Tips

1. **Reuse Engine Instances**: Create one engine and reset between uses
2. **Use try-with-resources**: Ensures native memory is properly released
3. **Batch Processing**: Process multiple items with the same engine
4. **Native Performance**: JNI bindings have minimal overhead
5. **Zero-Copy**: Text processing happens in Rust without copying

## API Reference

### GuardEngine

- `new GuardEngine()` - Create new engine
- `GuardEngine.withScoreThreshold(int)` - Create with scoring
- `.addForbiddenSequence(rule)` - Add sequence rule
- `.addPatternRule(rule)` - Add pattern rule
- `.feed(String chunk)` - Process text chunk
- `.reset()` - Reset state
- `.currentScore()` - Get current score
- `.close()` - Free native resources

### ForbiddenSequenceRule

- `ForbiddenSequenceRule.strict(String[], String)` - Strict sequence
- `ForbiddenSequenceRule.withGaps(String[], String)` - Allow gaps
- `ForbiddenSequenceRule.withScore(String[], String, int)` - With scoring

### PatternRule

- `PatternRule.email(String)` - Block emails
- `PatternRule.emailRewrite(String)` - Redact emails
- `PatternRule.url(String)` - Block URLs
- `PatternRule.urlRewrite(String)` - Redact URLs
- `PatternRule.ipv4(String)` - Block IPv4 addresses
- `PatternRule.creditCard(String)` - Block credit cards

### Decision

- `.isAllow()` - Check if allowed
- `.isBlock()` - Check if blocked
- `.isRewrite()` - Check if rewritten
- `.getReason()` - Get block reason (if blocked)
- `.getRewrittenText()` - Get rewritten text (if rewritten)

## System Requirements

- Java 8+
- Maven 3.6+
- Rust toolchain (for building)
- Native library in java.library.path

## Platform Support

- Linux (libstreamguard.so)
- macOS (libstreamguard.dylib)
- Windows (streamguard.dll)

## Notes

- Native Rust performance (no JVM overhead)
- Zero external dependencies
- Thread-safe (each engine instance is independent)
- Compatible with all Java frameworks (Spring, Jakarta EE, etc.)
- Automatic memory management with AutoCloseable
