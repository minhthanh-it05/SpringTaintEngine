package com.thanh.springtaint.rules;

import com.thanh.springtaint.callgraph.MethodKey;

import java.util.Set;

/**
 * A dangerous method: reaching it with tainted data at one of
 * {@code taintedArgumentIndexes} is the vulnerability.
 *
 * {@code className == null} matches {@code methodName} against any receiver class. This
 * exists because {@link com.thanh.springtaint.callgraph.CallGraphBuilder} can't resolve
 * the receiver class of a chained call such as {@code Runtime.getRuntime().exec(cmd)}
 * (the scope of {@code .exec(...)} is itself a method call, not a typed variable) -- it
 * records that callee as class {@code "?"}. A wildcard sink still catches it, at the cost
 * of being more prone to false positives on unrelated {@code exec(...)} methods.
 */
public record SinkRule(String className, String methodName, Set<Integer> taintedArgumentIndexes,
                        VulnerabilityType vulnerabilityType, String description) {

    /**
     * Sentinel argument index meaning "the call's receiver, not one of its arguments, is what
     * must be tainted" -- e.g. {@code taintedStream.readObject()}, where the danger is the
     * object the method is called ON, not anything passed into it. Must be listed explicitly
     * in {@link #taintedArgumentIndexes}; it is never implied by the "empty set = any argument"
     * wildcard below.
     */
    public static final int RECEIVER_INDEX = -1;

    public boolean matches(MethodKey callee) {
        return (className == null || className.equals(callee.className()))
                && methodName.equals(callee.methodName());
    }

    /** Empty {@link #taintedArgumentIndexes} means every argument position is sink-relevant. */
    public boolean isArgumentTainted(int argumentIndex) {
        if (argumentIndex == RECEIVER_INDEX) {
            return taintedArgumentIndexes.contains(RECEIVER_INDEX);
        }
        return taintedArgumentIndexes.isEmpty() || taintedArgumentIndexes.contains(argumentIndex);
    }
}
