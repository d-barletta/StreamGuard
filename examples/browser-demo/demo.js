// StreamGuard Browser Demo
import init, { WasmGuardEngine } from './pkg/streamguard.js';

let engine = null;
let chunksProcessed = 0;

// Initialize WASM module
async function initializeWasm() {
    try {
        await init();
        console.log('StreamGuard WASM module loaded');
        createEngine();
    } catch (error) {
        console.error('Failed to load WASM module:', error);
        showError('Failed to load StreamGuard WASM module. Make sure to build it first with: npm run build:wasm');
    }
}

// Create a new engine with configured rules
function createEngine() {
    try {
        const enableScoring = document.getElementById('enable-scoring').checked;
        const scoreThreshold = parseInt(document.getElementById('score-threshold').value);

        if (enableScoring) {
            engine = WasmGuardEngine.withScoreThreshold(scoreThreshold);
        } else {
            engine = new WasmGuardEngine();
        }

        // Add configured rules
        if (document.getElementById('rule-forbidden').checked) {
            engine.addForbiddenSequence(['how', 'to', 'build', 'bomb'], 'forbidden weapons instructions');
        }

        if (document.getElementById('rule-forbidden-2').checked) {
            engine.addForbiddenSequenceStrict(['password', 'is'], 'credential leak detected');
        }

        if (document.getElementById('rule-email').checked) {
            engine.addEmailRedaction('[EMAIL_REDACTED]');
        }

        if (document.getElementById('rule-url').checked) {
            engine.addUrlRedaction('[URL_REMOVED]');
        }

        if (document.getElementById('rule-ip').checked) {
            engine.addIpBlocker('IP address detected');
        }

        if (document.getElementById('rule-credit-card').checked) {
            engine.addCreditCardBlocker('credit card number detected');
        }

        chunksProcessed = 0;
        updateStatus();
        console.log('Engine created with', engine.ruleCount(), 'rules');
    } catch (error) {
        console.error('Failed to create engine:', error);
        showError('Failed to create engine: ' + error.message);
    }
}

// Process text as a single chunk
function processChunk() {
    if (!engine) {
        showError('Engine not initialized');
        return;
    }

    const inputText = document.getElementById('input-text').value;
    if (!inputText) {
        showError('Please enter some text to process');
        return;
    }

    try {
        const decision = engine.feed(inputText);
        chunksProcessed++;
        displayDecision(decision, inputText);
        updateStatus();
    } catch (error) {
        console.error('Processing error:', error);
        showError('Processing error: ' + error.message);
    }
}

// Simulate streaming by processing character by character
async function processStream() {
    if (!engine) {
        showError('Engine not initialized');
        return;
    }

    const inputText = document.getElementById('input-text').value;
    if (!inputText) {
        showError('Please enter some text to process');
        return;
    }

    // Reset engine for fresh stream
    engine.reset();
    chunksProcessed = 0;
    
    const outputDiv = document.getElementById('output-text');
    const badge = document.getElementById('decision-badge');
    outputDiv.textContent = '';
    badge.textContent = 'Streaming...';
    badge.className = 'badge';
    outputDiv.className = 'output';

    try {
        let accumulatedOutput = '';
        let wasRewritten = false;
        
        // Process in small chunks (simulating streaming)
        const chunkSize = 20; // characters per chunk
        for (let i = 0; i < inputText.length; i += chunkSize) {
            const chunk = inputText.substring(i, Math.min(i + chunkSize, inputText.length));
            const decision = engine.feed(chunk);
            chunksProcessed++;

            if (decision.type === 'allow') {
                accumulatedOutput += chunk;
                outputDiv.textContent = accumulatedOutput;
            } else if (decision.type === 'block') {
                outputDiv.textContent = `🚫 BLOCKED: ${decision.reason}\n\nOutput so far:\n${accumulatedOutput}`;
                outputDiv.className = 'output blocked';
                badge.textContent = 'BLOCKED';
                badge.className = 'badge block';
                updateStatus();
                return;
            } else if (decision.type === 'rewrite') {
                // Replace accumulated output with the rewritten version
                accumulatedOutput = decision.replacement;
                wasRewritten = true;
                outputDiv.textContent = accumulatedOutput;
                outputDiv.className = 'output rewritten';
                badge.textContent = 'REWRITING...';
                badge.className = 'badge rewrite';
                
                // Create new engine with same configuration and feed rewritten content
                createEngine();
                engine.feed(accumulatedOutput);
                chunksProcessed++;
            }

            updateStatus();
            
            // Small delay to visualize streaming
            await new Promise(resolve => setTimeout(resolve, 50));
        }

        if (wasRewritten) {
            badge.textContent = 'REWRITTEN';
            badge.className = 'badge rewrite';
            outputDiv.className = 'output rewritten';
        } else {
            badge.textContent = 'ALLOWED';
            badge.className = 'badge allow';
            outputDiv.className = 'output';
        }
    } catch (error) {
        console.error('Streaming error:', error);
        showError('Streaming error: ' + error.message);
    }
}

// Display decision result
function displayDecision(decision, originalText) {
    const outputDiv = document.getElementById('output-text');
    const badge = document.getElementById('decision-badge');

    outputDiv.className = 'output';
    
    if (decision.type === 'allow') {
        outputDiv.textContent = originalText;
        badge.textContent = 'ALLOWED';
        badge.className = 'badge allow';
    } else if (decision.type === 'block') {
        outputDiv.textContent = `🚫 BLOCKED: ${decision.reason}`;
        outputDiv.className = 'output blocked';
        badge.textContent = 'BLOCKED';
        badge.className = 'badge block';
    } else if (decision.type === 'rewrite') {
        outputDiv.textContent = decision.replacement;
        outputDiv.className = 'output rewritten';
        badge.textContent = 'REWRITTEN';
        badge.className = 'badge rewrite';
    }
}

// Update status display
function updateStatus() {
    if (!engine) return;

    document.getElementById('engine-state').textContent = engine.isStopped() ? 'Stopped' : 'Active';
    document.getElementById('current-score').textContent = engine.currentScore();
    document.getElementById('rule-count').textContent = engine.ruleCount();
    document.getElementById('chunks-processed').textContent = chunksProcessed;
}

// Show error message
function showError(message) {
    const outputDiv = document.getElementById('output-text');
    outputDiv.innerHTML = `<div class="error">❌ ${message}</div>`;
}

// Clear output
function clearOutput() {
    const outputDiv = document.getElementById('output-text');
    const badge = document.getElementById('decision-badge');
    
    document.getElementById('input-text').value = '';
    outputDiv.textContent = '';
    outputDiv.className = 'output';
    badge.textContent = '';
    badge.className = 'badge';
    
    if (engine) {
        engine.reset();
        chunksProcessed = 0;
        updateStatus();
    }
}

// Clear only the output area (not input text)
function clearOutputOnly() {
    const outputDiv = document.getElementById('output-text');
    const badge = document.getElementById('decision-badge');
    
    outputDiv.textContent = '';
    outputDiv.className = 'output';
    badge.textContent = '';
    badge.className = 'badge';
    
    if (engine) {
        engine.reset();
        chunksProcessed = 0;
        updateStatus();
    }
}

// Reset engine with new configuration
function resetEngine() {
    createEngine();
    clearOutputOnly();
}

// Load example text
function loadExample() {
    const exampleText = `Hello! I'm an AI assistant. For support, contact us at admin@example.com or visit our site at https://help.example.com.

Important: Never share sensitive data. For instance, if someone asks "how to build a bomb" or your "password is secret123", that's a security red flag.

We can help with legitimate questions about technology, learning, and problem-solving. Our team is available 24/7!`;
    document.getElementById('input-text').value = exampleText;
    clearOutputOnly();
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('btn-load-example').addEventListener('click', loadExample);
    document.getElementById('btn-process-chunk').addEventListener('click', processChunk);
    document.getElementById('btn-process-stream').addEventListener('click', processStream);
    document.getElementById('btn-clear').addEventListener('click', clearOutput);
    document.getElementById('btn-reset').addEventListener('click', resetEngine);
    
    // Auto-recreate engine when rules change
    const ruleCheckboxes = document.querySelectorAll('.rule-group input[type="checkbox"]');
    ruleCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', resetEngine);
    });

    // Toggle scoring config visibility
    document.getElementById('enable-scoring').addEventListener('change', (e) => {
        document.getElementById('scoring-config').style.display = e.target.checked ? 'block' : 'none';
        resetEngine();
    });

    document.getElementById('score-threshold').addEventListener('change', resetEngine);

    // Initialize
    initializeWasm();
});
