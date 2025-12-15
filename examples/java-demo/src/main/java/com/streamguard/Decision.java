package com.streamguard;

/**
 * Represents a decision made by the GuardEngine
 */
public class Decision {
    private final Type type;
    private final String reason;
    private final String rewrittenText;
    
    public enum Type {
        ALLOW,
        BLOCK,
        REWRITE
    }
    
    private Decision(Type type, String reason, String rewrittenText) {
        this.type = type;
        this.reason = reason;
        this.rewrittenText = rewrittenText;
    }
    
    public static Decision allow() {
        return new Decision(Type.ALLOW, null, null);
    }
    
    public static Decision block(String reason) {
        return new Decision(Type.BLOCK, reason, null);
    }
    
    public static Decision rewrite(String text) {
        return new Decision(Type.REWRITE, null, text);
    }
    
    public boolean isAllow() {
        return type == Type.ALLOW;
    }
    
    public boolean isBlock() {
        return type == Type.BLOCK;
    }
    
    public boolean isRewrite() {
        return type == Type.REWRITE;
    }
    
    public String getReason() {
        return reason;
    }
    
    public String getRewrittenText() {
        return rewrittenText;
    }
    
    @Override
    public String toString() {
        switch (type) {
            case ALLOW:
                return "Decision(ALLOW)";
            case BLOCK:
                return "Decision(BLOCK, reason='" + reason + "')";
            case REWRITE:
                return "Decision(REWRITE, text='" + 
                       (rewrittenText.length() > 20 ? rewrittenText.substring(0, 20) + "..." : rewrittenText) + "')";
            default:
                return "Decision(UNKNOWN)";
        }
    }
}
