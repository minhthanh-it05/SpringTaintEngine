package com.thanh.springtaint.rules;

import com.thanh.springtaint.callgraph.MethodKey;

/**
 * A call that neutralizes taint carried by one of its arguments: reaching it doesn't stop
 * the value from being used further downstream, but the value coming back out of it (its
 * return value, or -- for validators -- the same argument continuing on) is no longer
 * considered attacker-controlled.
 */
public record SanitizerRule(String className, String methodName, int sanitizedArgumentIndex, String description) {

    public boolean sanitizes(MethodKey callee, int argumentIndex) {
        return argumentIndex == sanitizedArgumentIndex
                && className.equals(callee.className())
                && methodName.equals(callee.methodName());
    }
}
