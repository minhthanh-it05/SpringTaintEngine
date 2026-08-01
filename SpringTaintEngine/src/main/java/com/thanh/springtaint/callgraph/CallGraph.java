package com.thanh.springtaint.callgraph;

import java.util.List;
import java.util.Set;

public record CallGraph(Set<MethodKey> declaredMethods, List<CallGraphEdge> edges) {

    /** True when {@code key} isn't backed by a method declaration in the parsed sources. */
    public boolean isExternal(MethodKey key) {
        return !declaredMethods.contains(key);
    }
}
