package com.thanh.springtaint.callgraph;

public record MethodKey(String className, String methodName, int paramCount) {
    @Override
    public String toString() {
        return className + "." + methodName + "/" + paramCount;
    }
}
