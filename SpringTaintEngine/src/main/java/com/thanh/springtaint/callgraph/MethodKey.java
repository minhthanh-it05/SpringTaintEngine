package com.thanh.springtaint.callgraph;

public record MethodKey(String className, String methodName, int paramCount) {

    /** The JVM's own name for a constructor -- used as {@code methodName} for constructor callees. */
    public static final String CONSTRUCTOR_METHOD_NAME = "<init>";

    @Override
    public String toString() {
        return className + "." + methodName + "/" + paramCount;
    }
}
