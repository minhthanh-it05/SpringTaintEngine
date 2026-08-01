package com.thanh.springtaint.taint;

import com.thanh.springtaint.callgraph.MethodKey;
import com.thanh.springtaint.rules.SinkRule;
import com.thanh.springtaint.rules.TaintedParameter;

import java.util.List;

/** A confirmed Source-to-Sink taint path, with the full hop-by-hop path for explainability. */
public record TaintFinding(MethodKey sourceMethod, TaintedParameter source, MethodKey sinkMethod,
                            SinkRule sinkRule, String sinkCallSite, List<PathStep> path) {
}
