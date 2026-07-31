package com.thanh.springtaint.cfg;

import java.util.List;

public record ControlFlowGraph(CfgNode entry, CfgNode exit, List<CfgNode> nodes, List<CfgEdge> edges) {
}
