package com.thanh.springtaint.taint;

import com.thanh.springtaint.callgraph.MethodKey;

/** Identifies one DFG node within one specific method, for cross-method taint tracking. */
record NodeRef(MethodKey method, int nodeId) {
}
