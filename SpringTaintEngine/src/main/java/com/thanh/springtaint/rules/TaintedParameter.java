package com.thanh.springtaint.rules;

/**
 * A method parameter identified as a taint Source: its position matches the id of the
 * corresponding PARAM node a {@link com.thanh.springtaint.dfg.DfgBuilder} creates for
 * that method, since both walk {@code method.getParameters()} in the same order.
 */
public record TaintedParameter(int index, String parameterName, String sourceAnnotation) {
}
