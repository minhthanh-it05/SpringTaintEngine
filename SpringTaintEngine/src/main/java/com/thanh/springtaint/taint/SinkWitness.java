package com.thanh.springtaint.taint;

import com.thanh.springtaint.callgraph.MethodKey;
import com.thanh.springtaint.rules.SinkRule;

import java.util.List;

/**
 * One concrete sink a {@link MethodSummary} proves reachable when its parameter is tainted:
 * which {@link SinkRule} matched, the callee the matching call site resolved to, the call-site
 * text, and the hop-by-hop path from the summarized method's own tainted parameter up to (and
 * including) that call. The path is reused verbatim by every caller whose own argument triggers
 * this summary -- what happens *inside* the summarized method is the same regardless of who
 * called it; only the caller-side prefix differs, and callers splice that on themselves (see
 * {@code TaintEngine#walkMethod}).
 */
record SinkWitness(SinkRule sinkRule, MethodKey sinkCalleeMethod, String sinkCallSite, List<PathStep> path) {
}
