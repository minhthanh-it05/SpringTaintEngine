package com.thanh.springtaint.taint;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.thanh.springtaint.callgraph.CallGraph;
import com.thanh.springtaint.callgraph.CallGraphBuilder;
import com.thanh.springtaint.callgraph.CallGraphEdge;
import com.thanh.springtaint.callgraph.MethodKey;
import com.thanh.springtaint.dfg.DataFlowGraph;
import com.thanh.springtaint.dfg.DfgBuilder;
import com.thanh.springtaint.dfg.DfgEdge;
import com.thanh.springtaint.dfg.DfgNode;
import com.thanh.springtaint.rules.SinkRule;
import com.thanh.springtaint.rules.TaintRules;
import com.thanh.springtaint.rules.TaintedParameter;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Whole-project, interprocedural taint propagation.
 *
 * Runs a worklist reachability analysis over a graph stitched together from every
 * parsed method's DFG (M5) via the Call Graph (M6): a tainted value that flows into an
 * argument of a call to an internally-declared method jumps into that callee's matching
 * PARAM node, and a tainted RETURN jumps back into the CALL node it was entered from (see
 * "1-call-site-sensitive" below). Whenever taint reaches an argument position of a call that
 * matches a registered {@link SinkRule} (M7), a {@link TaintFinding} is recorded with
 * the full source-to-sink path.
 *
 * The correlation between a DFG {@code CALL} node and the {@link MethodKey}(s) it
 * resolves to is done by matching call-site text ({@code MethodCallExpr.toString()})
 * against the Call Graph's edges for that caller, rather than re-implementing
 * scope/type resolution here -- reuses CallGraphBuilder's resolution as the single
 * source of truth instead of risking the two builders disagreeing. A call site can
 * resolve to more than one callee (CallGraphBuilder fans an interface/abstract call out
 * to every concrete override it can find), in which case taint is propagated into
 * -- and sinks are checked against -- every one of them.
 *
 * Sanitizer-aware: when every callee a call site resolves to is a registered
 * {@link com.thanh.springtaint.rules.SanitizerRule} for the tainted argument position (M-B1),
 * taint stops there instead of continuing into the call's result -- e.g. an SQL string built
 * from {@code Integer.parseInt(id)} isn't reported as reaching a sink further down.
 *
 * 1-call-site-sensitive: a {@link NodeRef} carries the single call site it was entered
 * through (see its javadoc), so when taint returns from a callee it jumps back into that
 * *specific* caller, not into every caller of that method. This is a real precision
 * improvement over broadcasting to every call site, but it is truncated to depth 1: once
 * taint crosses a second method boundary the recorded context is discarded and propagation
 * reverts to broadcasting from there on. A full call-stack-sensitive (k=∞) analysis would
 * remove this residual imprecision at the cost of a potentially unbounded state space.
 *
 * Known trade-offs (same "get it running end-to-end first" spirit as the
 * simplifications already documented on CfgBuilder/DfgBuilder/CallGraphBuilder):
 * - One parent pointer per node: when two different sources both flow into the same
 *   downstream node (e.g. two tainted parameters concatenated together), only the
 *   first-discovered path is kept for reporting, even though both origins do reach the
 *   sink. A full multi-source tabulation (IFDS-style) would remove this.
 * - Only call sites that {@link DfgBuilder} actually models (see its javadoc on
 *   unhandled expression forms) can be jumped through or matched as a sink.
 */
public class TaintEngine {

    private final TaintRules rules;
    private final CallGraph callGraph;
    private final Map<MethodKey, MethodDeclaration> methodsByKey = new HashMap<>();
    private final Map<MethodKey, DataFlowGraph> dfgByKey = new HashMap<>();
    private final Map<MethodKey, Map<String, Set<MethodKey>>> calleeBySite = new HashMap<>();
    private final Map<MethodKey, List<NodeRef>> callSitesByCallee = new HashMap<>();

    public TaintEngine(List<CompilationUnit> units, TaintRules rules) {
        this.rules = rules;

        for (CompilationUnit unit : units) {
            for (TypeDeclaration<?> typeDecl : unit.findAll(TypeDeclaration.class)) {
                String className = typeDecl.getNameAsString();
                for (MethodDeclaration method : typeDecl.getMethods()) {
                    MethodKey key = new MethodKey(className, method.getNameAsString(), method.getParameters().size());
                    methodsByKey.put(key, method);
                    dfgByKey.put(key, new DfgBuilder().build(method));
                }
            }
        }

        // A call site can resolve to more than one callee: CallGraphBuilder fans an
        // interface/abstract dispatch out to every concrete override it can find (see its
        // javadoc), emitting one CallGraphEdge per candidate for the same call site text.
        this.callGraph = new CallGraphBuilder().build(units);
        for (CallGraphEdge edge : callGraph.edges()) {
            calleeBySite.computeIfAbsent(edge.caller(), k -> new HashMap<>())
                    .computeIfAbsent(edge.callSite(), k -> new LinkedHashSet<>())
                    .add(edge.callee());
        }

        for (Map.Entry<MethodKey, DataFlowGraph> entry : dfgByKey.entrySet()) {
            MethodKey caller = entry.getKey();
            Map<String, Set<MethodKey>> sites = calleeBySite.getOrDefault(caller, Map.of());
            for (DfgNode node : entry.getValue().nodes()) {
                if (node.kind() != DfgNode.Kind.CALL) {
                    continue;
                }
                for (MethodKey callee : sites.getOrDefault(node.label(), Set.of())) {
                    callSitesByCallee.computeIfAbsent(callee, k -> new ArrayList<>())
                            .add(new NodeRef(caller, node.id()));
                }
            }
        }
    }

    /** The declaration backing {@code key}, or null when {@code key} isn't one of the parsed methods (e.g. an external sink). */
    public MethodDeclaration methodDeclaration(MethodKey key) {
        return methodsByKey.get(key);
    }

    public List<TaintFinding> analyze() {
        Set<NodeRef> visited = new LinkedHashSet<>();
        Map<NodeRef, NodeRef> cameFrom = new HashMap<>();
        Map<NodeRef, TaintedParameter> rootSource = new HashMap<>();
        Deque<NodeRef> worklist = new ArrayDeque<>();
        List<TaintFinding> findings = new ArrayList<>();

        for (Map.Entry<MethodKey, MethodDeclaration> entry : methodsByKey.entrySet()) {
            MethodKey method = entry.getKey();
            for (TaintedParameter source : rules.sources().findSources(entry.getValue())) {
                DfgNode paramNode = dfgByKey.get(method).paramNode(source.index());
                NodeRef ref = new NodeRef(method, paramNode.id());
                if (visited.add(ref)) {
                    cameFrom.put(ref, null);
                    rootSource.put(ref, source);
                    worklist.add(ref);
                }
            }
        }

        while (!worklist.isEmpty()) {
            NodeRef current = worklist.poll();
            DataFlowGraph dfg = dfgByKey.get(current.method());
            DfgNode currentNode = dfg.node(current.nodeId());

            if (currentNode.kind() == DfgNode.Kind.RETURN) {
                // With a specific entry call site recorded (context != null), return there and
                // only there. Otherwise (context-free: a source-originating return, or context
                // already spent one hop earlier) fall back to broadcasting to every known call
                // site of this method, same as the fully context-insensitive behavior.
                List<NodeRef> returnTargets = current.context() != null
                        ? List.of(new NodeRef(current.context().callerMethod(), current.context().callerCallNodeId()))
                        : callSitesByCallee.getOrDefault(current.method(), List.of());
                for (NodeRef callSite : returnTargets) {
                    if (visited.add(callSite)) {
                        cameFrom.put(callSite, current);
                        worklist.add(callSite);
                    }
                }
            }

            for (DfgEdge edge : dfg.edges()) {
                if (edge.from().id() != currentNode.id()) {
                    continue;
                }
                DfgNode to = edge.to();
                // Still inside the same call frame -- carries the same context as current.
                NodeRef toRef = new NodeRef(current.method(), to.id(), current.context());

                boolean isArgEdge = to.kind() == DfgNode.Kind.CALL && edge.label() != null && edge.label().startsWith("arg");
                boolean isReceiverEdge = to.kind() == DfgNode.Kind.CALL && "receiver".equals(edge.label());
                if (!isArgEdge && !isReceiverEdge) {
                    if (visited.add(toRef)) {
                        cameFrom.put(toRef, current);
                        worklist.add(toRef);
                    }
                    continue;
                }

                int argumentIndex = isReceiverEdge ? SinkRule.RECEIVER_INDEX : Integer.parseInt(edge.label().substring(3));
                Set<MethodKey> callees = calleeBySite.getOrDefault(current.method(), Map.of())
                        .getOrDefault(to.label(), Set.of());

                boolean sanitizedByEveryCallee = !callees.isEmpty() && argumentIndex != SinkRule.RECEIVER_INDEX
                        && callees.stream().allMatch(callee -> rules.sanitizers().sanitizes(callee, argumentIndex));
                if (sanitizedByEveryCallee) {
                    continue; // neutralized here: don't mark the call node (or its downstream) tainted
                }

                if (visited.add(toRef)) {
                    cameFrom.put(toRef, current);
                    worklist.add(toRef);
                }

                for (MethodKey callee : callees) {
                    recordSinkHits(current, to, argumentIndex, callee, cameFrom, rootSource, findings);
                    if (argumentIndex != SinkRule.RECEIVER_INDEX) {
                        jumpIntoCallee(callee, argumentIndex, current, to, visited, cameFrom, worklist);
                    }
                }
            }
        }

        return findings;
    }

    private void recordSinkHits(NodeRef argSource, DfgNode callNode, int argumentIndex, MethodKey callee,
                                 Map<NodeRef, NodeRef> cameFrom, Map<NodeRef, TaintedParameter> rootSource,
                                 List<TaintFinding> findings) {
        for (SinkRule sinkRule : rules.sinks().match(callee)) {
            if (!sinkRule.isArgumentTainted(argumentIndex)) {
                continue;
            }
            List<NodeRef> refs = reconstructPath(argSource, cameFrom);
            NodeRef rootRef = refs.get(0);

            List<PathStep> path = new ArrayList<>();
            for (NodeRef ref : refs) {
                path.add(new PathStep(ref.method(), dfgByKey.get(ref.method()).node(ref.nodeId())));
            }
            path.add(new PathStep(argSource.method(), callNode));

            findings.add(new TaintFinding(rootRef.method(), rootSource.get(rootRef), callee, sinkRule,
                    callNode.label(), path));
        }
    }

    private void jumpIntoCallee(MethodKey callee, int argumentIndex, NodeRef current, DfgNode callNode,
                                 Set<NodeRef> visited, Map<NodeRef, NodeRef> cameFrom, Deque<NodeRef> worklist) {
        if (callGraph.isExternal(callee)) {
            return;
        }
        DataFlowGraph calleeDfg = dfgByKey.get(callee);
        long paramCount = calleeDfg.nodes().stream().filter(n -> n.kind() == DfgNode.Kind.PARAM).count();
        if (argumentIndex >= paramCount) {
            return;
        }
        DfgNode calleeParamNode = calleeDfg.paramNode(argumentIndex);
        // Depth-1 truncation: the callee's context is exactly this call site, regardless of
        // whatever context `current` itself was carrying.
        NodeRef.CallSite context = new NodeRef.CallSite(current.method(), callNode.id());
        NodeRef calleeRef = new NodeRef(callee, calleeParamNode.id(), context);
        if (visited.add(calleeRef)) {
            cameFrom.put(calleeRef, current);
            worklist.add(calleeRef);
        }
    }

    private List<NodeRef> reconstructPath(NodeRef end, Map<NodeRef, NodeRef> cameFrom) {
        List<NodeRef> refs = new ArrayList<>();
        for (NodeRef cur = end; cur != null; cur = cameFrom.get(cur)) {
            refs.add(cur);
        }
        Collections.reverse(refs);
        return refs;
    }
}
