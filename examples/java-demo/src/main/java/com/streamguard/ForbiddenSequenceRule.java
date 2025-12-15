package com.streamguard;

import java.util.Arrays;
import java.util.List;

/**
 * Rule for detecting forbidden token sequences
 */
public class ForbiddenSequenceRule {
    static {
        System.loadLibrary("streamguard");
    }
    
    private final long nativeHandle;
    
    private ForbiddenSequenceRule(long handle) {
        this.nativeHandle = handle;
    }
    
    public static ForbiddenSequenceRule strict(List<String> tokens, String reason) {
        long handle = nativeStrict(tokens, reason);
        return new ForbiddenSequenceRule(handle);
    }
    
    public static ForbiddenSequenceRule strict(String[] tokens, String reason) {
        return strict(Arrays.asList(tokens), reason);
    }
    
    public static ForbiddenSequenceRule withGaps(List<String> tokens, String reason) {
        long handle = nativeWithGaps(tokens, reason);
        return new ForbiddenSequenceRule(handle);
    }
    
    public static ForbiddenSequenceRule withGaps(String[] tokens, String reason) {
        return withGaps(Arrays.asList(tokens), reason);
    }
    
    public static ForbiddenSequenceRule withScore(List<String> tokens, String reason, int score) {
        long handle = nativeWithScore(tokens, reason, score);
        return new ForbiddenSequenceRule(handle);
    }
    
    public static ForbiddenSequenceRule withScore(String[] tokens, String reason, int score) {
        return withScore(Arrays.asList(tokens), reason, score);
    }
    
    long getNativeHandle() {
        return nativeHandle;
    }
    
    // Native methods
    private static native long nativeStrict(List<String> tokens, String reason);
    private static native long nativeWithGaps(List<String> tokens, String reason);
    private static native long nativeWithScore(List<String> tokens, String reason, int score);
}
