package com.thanh.springtaint.callgraph;

public record CallGraphEdge(MethodKey caller, MethodKey callee, String callSite) {
}
