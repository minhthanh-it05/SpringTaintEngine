package com.thanh.springtaint.dfg;

import java.util.List;

public record DataFlowGraph(List<DfgNode> nodes, List<DfgEdge> edges) {

    /** Node ids are assigned 0..n-1 in the order they were created, matching list position. */
    public DfgNode node(int id) {
        return nodes.get(id);
    }

    /** The PARAM node for the method parameter at {@code parameterIndex}, in declaration order. */
    public DfgNode paramNode(int parameterIndex) {
        return nodes.stream()
                .filter(node -> node.kind() == DfgNode.Kind.PARAM)
                .toList()
                .get(parameterIndex);
    }
}
