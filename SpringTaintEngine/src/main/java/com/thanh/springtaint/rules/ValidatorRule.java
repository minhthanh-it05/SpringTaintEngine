package com.thanh.springtaint.rules;

/**
 * A boolean-returning call that, when used as an {@code if} condition, proves one of its
 * arguments safe on the branch where the call is known to have returned {@code true} -- e.g.
 * {@code StringUtils.isNumeric(value)} returning true means {@code value} contains only
 * digits, which cannot carry an injection payload.
 *
 * Unlike {@link SanitizerRule} (which neutralizes taint on the call's own result, consumed
 * immediately at that call site), a validator's own result is a throwaway boolean -- what
 * actually gets cleared is the *original variable* passed into it, and only within the branch
 * where the check is known to have passed. Applying that correctly requires the caller
 * (DfgBuilder) to know which branch that is; see {@code DfgBuilder#processIf}.
 */
public record ValidatorRule(String className, String methodName, int valueArgumentIndex, String rationale) {

    public boolean matches(String scopeSimpleName, String calledMethodName) {
        return methodName.equals(calledMethodName)
                && className.equals(scopeSimpleName);
    }
}
