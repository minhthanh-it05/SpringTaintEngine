package com.thanh.springtaint.rules;

import com.thanh.springtaint.callgraph.MethodKey;

/**
 * A call that neutralizes taint carried by one of its arguments: reaching it doesn't stop
 * the value from being used further downstream, but the value coming back out of it (its
 * return value, or -- for validators -- the same argument continuing on) is no longer
 * considered attacker-controlled.
 */
public record SanitizerRule(String className, String methodName, int sanitizedArgumentIndex, String description) {

    /**
     * Sentinel meaning "the call's receiver, not one of its arguments, carries the taint that
     * gets neutralized" -- e.g. {@code new File(path).getName()}, where the danger is the
     * object the method is called ON (mirrors {@link SinkRule#RECEIVER_INDEX}).
     */
    public static final int RECEIVER_INDEX = SinkRule.RECEIVER_INDEX;

    public boolean sanitizes(MethodKey callee, int argumentIndex) {
        return argumentIndex == sanitizedArgumentIndex
                && className.equals(callee.className())
                && methodName.equals(callee.methodName());
    }
}
