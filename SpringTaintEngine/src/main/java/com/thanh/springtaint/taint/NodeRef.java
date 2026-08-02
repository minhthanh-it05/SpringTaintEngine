package com.thanh.springtaint.taint;

import com.thanh.springtaint.callgraph.MethodKey;

/**
 * Identifies one DFG node within one specific method, together with the single call site it
 * was reached through -- 1-call-site-sensitivity (see {@link TaintEngine}'s javadoc).
 * {@code context} is null for a node reached without crossing a method boundary (taint
 * sources, and anything more than one call frame removed from the entry call site: context
 * is deliberately truncated to depth 1 rather than carried as a full call stack, to keep the
 * worklist's state space finite).
 */
record NodeRef(MethodKey method, int nodeId, CallSite context) {

    NodeRef(MethodKey method, int nodeId) {
        this(method, nodeId, null);
    }

    /** The one call site (caller method + its CALL node id) a callee's PARAM node was entered through. */
    record CallSite(MethodKey callerMethod, int callerCallNodeId) {
    }
}
