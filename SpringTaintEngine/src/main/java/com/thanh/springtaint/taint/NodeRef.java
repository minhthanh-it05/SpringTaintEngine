package com.thanh.springtaint.taint;

import com.thanh.springtaint.callgraph.MethodKey;

import java.util.List;

/**
 * Identifies one DFG node within one specific method, together with the chain of call sites
 * it was reached through -- bounded call-site sensitivity (see {@link TaintEngine}'s javadoc).
 * {@code context} holds the most recent call frames, innermost first, capped at
 * {@link #MAX_CONTEXT_DEPTH}: entering a callee prepends a new frame and drops anything past
 * the cap, so state stays finite even under recursion. An empty context means either a taint
 * source (nothing to return to) or that context has been fully "spent" by returning through
 * {@link #MAX_CONTEXT_DEPTH} call boundaries already -- from there propagation degrades to
 * broadcasting to every call site of a method, same as a fully context-insensitive analysis.
 */
record NodeRef(MethodKey method, int nodeId, List<CallSite> context) {

    static final int MAX_CONTEXT_DEPTH = 4;

    NodeRef(MethodKey method, int nodeId) {
        this(method, nodeId, List.of());
    }

    /** One call site: the caller method and its CALL node id. */
    record CallSite(MethodKey callerMethod, int callerCallNodeId) {
    }
}
