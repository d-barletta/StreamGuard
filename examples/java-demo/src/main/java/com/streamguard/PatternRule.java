package com.streamguard;

/**
 * Rule for detecting patterns (email, URL, etc.)
 */
public class PatternRule {
    static {
        System.loadLibrary("streamguard");
    }
    
    private final long nativeHandle;
    
    private PatternRule(long handle) {
        this.nativeHandle = handle;
    }
    
    public static PatternRule email(String reason) {
        long handle = nativeEmail(reason);
        return new PatternRule(handle);
    }
    
    public static PatternRule emailRewrite(String replacement) {
        long handle = nativeEmailRewrite(replacement);
        return new PatternRule(handle);
    }
    
    public static PatternRule url(String reason) {
        long handle = nativeUrl(reason);
        return new PatternRule(handle);
    }
    
    public static PatternRule urlRewrite(String replacement) {
        long handle = nativeUrlRewrite(replacement);
        return new PatternRule(handle);
    }
    
    public static PatternRule ipv4(String reason) {
        long handle = nativeIpv4(reason);
        return new PatternRule(handle);
    }
    
    public static PatternRule creditCard(String reason) {
        long handle = nativeCreditCard(reason);
        return new PatternRule(handle);
    }
    
    long getNativeHandle() {
        return nativeHandle;
    }
    
    // Native methods
    private static native long nativeEmail(String reason);
    private static native long nativeEmailRewrite(String replacement);
    private static native long nativeUrl(String reason);
    private static native long nativeUrlRewrite(String replacement);
    private static native long nativeIpv4(String reason);
    private static native long nativeCreditCard(String reason);
}
