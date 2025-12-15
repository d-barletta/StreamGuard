package com.streamguard;

/**
 * StreamGuard engine for applying guardrails to text streams
 */
public class GuardEngine implements AutoCloseable {
    static {
        System.loadLibrary("streamguard");
    }
    
    private long nativeHandle;
    
    public GuardEngine() {
        this.nativeHandle = nativeNew();
    }
    
    public GuardEngine(int scoreThreshold) {
        this.nativeHandle = nativeNewWithThreshold(scoreThreshold);
    }
    
    public static GuardEngine withScoreThreshold(int threshold) {
        return new GuardEngine(threshold);
    }
    
    public Decision feed(String chunk) {
        if (nativeHandle == 0) {
            throw new IllegalStateException("Engine has been closed");
        }
        return nativeFeed(nativeHandle, chunk);
    }
    
    public void reset() {
        if (nativeHandle == 0) {
            throw new IllegalStateException("Engine has been closed");
        }
        nativeReset(nativeHandle);
    }
    
    public int currentScore() {
        if (nativeHandle == 0) {
            throw new IllegalStateException("Engine has been closed");
        }
        return nativeCurrentScore(nativeHandle);
    }
    
    public void addForbiddenSequence(ForbiddenSequenceRule rule) {
        if (nativeHandle == 0) {
            throw new IllegalStateException("Engine has been closed");
        }
        nativeAddForbiddenSequence(nativeHandle, rule.getNativeHandle());
    }
    
    public void addPatternRule(PatternRule rule) {
        if (nativeHandle == 0) {
            throw new IllegalStateException("Engine has been closed");
        }
        nativeAddPatternRule(nativeHandle, rule.getNativeHandle());
    }
    
    @Override
    public void close() {
        if (nativeHandle != 0) {
            nativeDestroy(nativeHandle);
            nativeHandle = 0;
        }
    }
    
    @Override
    public String toString() {
        return "GuardEngine(score=" + currentScore() + ")";
    }
    
    // Native methods
    private static native long nativeNew();
    private static native long nativeNewWithThreshold(int threshold);
    private native Decision nativeFeed(long handle, String chunk);
    private native void nativeReset(long handle);
    private native int nativeCurrentScore(long handle);
    private native void nativeAddForbiddenSequence(long handle, long ruleHandle);
    private native void nativeAddPatternRule(long handle, long ruleHandle);
    private native void nativeDestroy(long handle);
}
