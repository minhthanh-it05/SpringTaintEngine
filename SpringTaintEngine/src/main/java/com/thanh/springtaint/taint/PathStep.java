package com.thanh.springtaint.taint;

import com.thanh.springtaint.callgraph.MethodKey;
import com.thanh.springtaint.dfg.DfgNode;

/** One hop of a reported taint path: a DFG node, and which method it belongs to. */
public record PathStep(MethodKey method, DfgNode node) {
}
