package com.thanh.springtaint.taint;

import java.util.List;

/**
 * The memoized, calling-context-independent effect of "this one parameter of this one method is
 * tainted": every sink that reaches (with a witness path proving it, see {@link SinkWitness}),
 * and whether the method's own return value becomes tainted as a result -- which is what lets a
 * caller keep propagating past the call site without ever re-walking the callee's DFG, and
 * without needing to remember which call site to unwind back to afterward.
 *
 * This is what replaced {@code NodeRef}'s old bounded call-site-sensitivity (a fixed-depth
 * call-stack carried on every in-flight node, capped and degrading to a context-insensitive
 * broadcast beyond that cap): a summary is computed at most once per (method, parameter index)
 * pair, reused by every caller, and imposes no depth limit at all -- see {@code TaintEngine}'s
 * class javadoc for the full rationale.
 */
record MethodSummary(boolean returnTainted, List<SinkWitness> sinkWitnesses) {

    static final MethodSummary EMPTY = new MethodSummary(false, List.of());
}
