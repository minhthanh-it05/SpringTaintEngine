package com.thanh.springtaint.taint;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
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
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Whole-project, interprocedural taint propagation, computed via memoized per-method
 * {@link MethodSummary}s rather than walking into every callee's DFG at every call site.
 *
 * For each internally-declared method and each of its parameter positions, a summary answers
 * one context-independent question once: "if this parameter is tainted, which sinks does that
 * reach (transitively, through whatever this method itself calls), and does the method's own
 * return value become tainted as a result?" ({@link #computeSummary}). A caller whose own
 * argument is tainted just looks the callee's summary up ({@link #walkMethod}) -- splicing the
 * summary's own witness path onto its own for any sink reported, and continuing to propagate
 * past the call site only when the summary says the return is actually tainted -- instead of
 * re-deriving any of that by walking the callee's DFG itself. A summary is computed at most
 * once per (method, parameter index) pair no matter how many call sites reach it, so the whole
 * analysis is roughly linear in program size rather than exponential in call-chain depth.
 *
 * This replaced an earlier design where a taint value carried a bounded call-site stack (a
 * "NodeRef" identifying a DFG node together with up to 4 call frames of context) so a tainted
 * RETURN could jump back to the exact call site it came from; beyond that fixed depth,
 * propagation degraded to broadcasting a method's RETURN to every one of its call sites,
 * regardless of which one actually supplied the tainted argument -- imprecise (not unsound: the
 * old worklist never removed reachable nodes, so nothing was ever missed by hitting the cap,
 * only over-reported past it) for any call chain deeper than 4 hops, and an arbitrary number to
 * begin with. Summaries have no depth limit at all: {@code aTainted -> b -> c -> d -> e -> f}
 * resolves exactly regardless of chain length, and a summary's own recursion naturally answers
 * "which call site does this taint belong to" by construction -- a caller only ever consults the
 * summary for the argument position *it itself* proved tainted, so an unrelated sibling caller
 * passing an untainted argument into the same shared method never triggers it (see
 * {@code TaintEngineTest#analyze_contextSensitivity_doesNotLeakTaintIntoAnUnrelatedCallersSink}
 * and {@code #analyze_boundedContextSensitivity_avoidsFalsePositiveTwoHopsDeep}, both still
 * passing under this design with no depth-dependent caveat left to document).
 *
 * One behavior change from the old design, worth calling out explicitly: the old worklist added
 * *every* call node reached by a tainted argument to the propagation frontier unconditionally,
 * even when the callee's own body provably never lets that argument influence its return (e.g.
 * {@code void log(String msg) { }}) -- a blunt "assume opaque calls might return tainted data"
 * default that was really only meaningful for genuinely external/unresolvable calls. Now that a
 * summary can answer this precisely for every internally-declared callee, propagation past an
 * internal call site is gated on {@link MethodSummary#returnTainted()} instead -- strictly more
 * precise, not less recall (see each catalog/DfgBuilder javadoc for the analogous "don't
 * silently trust a validation that was never proven" reasoning applied here to call returns).
 * External/unresolved calls keep the old conservative default (always assume possibly tainted),
 * since there's no body to summarize at all.
 *
 * Recursion (a method whose own call graph eventually calls back into a summary already being
 * computed) is broken with an optimistic, empty placeholder rather than a full fixed-point
 * iteration -- see {@link #computeSummary}'s javadoc for exactly what that does and doesn't
 * cover.
 *
 * Everything downstream of "which node reached which node" -- CHA-based interface/abstract
 * dispatch fan-out, sanitizer-aware call-argument neutralization, {@link SinkRule#RECEIVER_INDEX}
 * handling -- carries over unchanged from the DFG/CallGraph layers this builds on.
 */
public class TaintEngine {

    private final TaintRules rules;
    private final CallGraph callGraph;
    private final Map<MethodKey, CallableDeclaration<?>> callablesByKey = new HashMap<>();
    private final Map<MethodKey, DataFlowGraph> dfgByKey = new HashMap<>();
    private final Map<MethodKey, Map<String, Set<MethodKey>>> calleeBySite = new HashMap<>();

    private final Map<ParamKey, MethodSummary> summaryCache = new HashMap<>();
    private final Set<ParamKey> summariesInProgress = new HashSet<>();

    public TaintEngine(List<CompilationUnit> units, TaintRules rules) {
        this.rules = rules;

        for (CompilationUnit unit : units) {
            for (TypeDeclaration<?> typeDecl : unit.findAll(TypeDeclaration.class)) {
                String className = typeDecl.getNameAsString();
                for (MethodDeclaration method : typeDecl.getMethods()) {
                    MethodKey key = new MethodKey(className, method.getNameAsString(), method.getParameters().size());
                    callablesByKey.put(key, method);
                    dfgByKey.put(key, new DfgBuilder().build(method));
                }
                if (typeDecl instanceof ClassOrInterfaceDeclaration classOrInterface) {
                    for (ConstructorDeclaration constructor : classOrInterface.getConstructors()) {
                        MethodKey key = new MethodKey(className, MethodKey.CONSTRUCTOR_METHOD_NAME,
                                constructor.getParameters().size());
                        callablesByKey.put(key, constructor);
                        dfgByKey.put(key, new DfgBuilder().build(constructor));
                    }
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
    }

    /** The declaration backing {@code key} (method or constructor), or null when {@code key} isn't one of the parsed callables (e.g. an external sink). */
    public CallableDeclaration<?> methodDeclaration(MethodKey key) {
        return callablesByKey.get(key);
    }

    public List<TaintFinding> analyze() {
        List<TaintFinding> findings = new ArrayList<>();
        for (Map.Entry<MethodKey, CallableDeclaration<?>> entry : callablesByKey.entrySet()) {
            MethodKey method = entry.getKey();
            for (TaintedParameter source : rules.sources().findSources(entry.getValue())) {
                MethodSummary summary = computeSummary(method, source.index());
                for (SinkWitness witness : summary.sinkWitnesses()) {
                    findings.add(new TaintFinding(method, source, witness.sinkCalleeMethod(),
                            witness.sinkRule(), witness.sinkCallSite(), witness.path()));
                }
            }
        }
        return findings;
    }

    /**
     * Returns the memoized summary for "parameter {@code paramIndex} of {@code method} is
     * tainted", computing it via {@link #walkMethod} on first request and caching the result --
     * every later caller (a real annotated source landing here as {@code (method, paramIndex)}
     * too, since a source and a summary consumer ask the exact same question) reuses it without
     * re-walking {@code method}'s DFG.
     *
     * Recursion guard: if this exact {@code (method, paramIndex)} is already being computed
     * higher up the current call stack (direct or mutual recursion), returns
     * {@link MethodSummary#EMPTY} instead of recursing forever. This is a narrow, deliberate
     * under-approximation -- not a full fixed-point iteration over the recursive cycle -- so a
     * sink reachable only by unwinding the recursion itself (vanishingly rare in the Spring MVC
     * request-handling code this engine targets) can be missed. A sink reachable directly within
     * the method, or via any non-recursive call it makes, is unaffected: that's found by the
     * very walk this guard is protecting, which keeps running to completion regardless of the
     * placeholder returned for the cyclic edge.
     */
    private MethodSummary computeSummary(MethodKey method, int paramIndex) {
        ParamKey key = new ParamKey(method, paramIndex);
        MethodSummary cached = summaryCache.get(key);
        if (cached != null) {
            return cached;
        }
        if (!summariesInProgress.add(key)) {
            return MethodSummary.EMPTY;
        }
        MethodSummary summary = walkMethod(method, paramIndex);
        summariesInProgress.remove(key);
        summaryCache.put(key, summary);
        return summary;
    }

    /**
     * The shared worklist: starting from {@code method}'s own {@code paramIndex}-th PARAM node,
     * walks {@code method}'s DFG (edges only, no cross-method jumping) to answer exactly what
     * {@link MethodSummary} promises. Used identically whether the caller is {@link #analyze()}
     * asking about a real annotated source or {@link #computeSummary} asking on some other
     * caller's behalf -- there is nothing source-specific about the walk itself, only about
     * what {@link #analyze()} does with the resulting witnesses afterward.
     */
    private MethodSummary walkMethod(MethodKey method, int paramIndex) {
        DataFlowGraph dfg = dfgByKey.get(method);
        DfgNode paramNode = dfg.paramNode(paramIndex);

        Set<Integer> visited = new LinkedHashSet<>();
        Map<Integer, Integer> cameFrom = new HashMap<>();
        Deque<Integer> worklist = new ArrayDeque<>();
        List<SinkWitness> sinkWitnesses = new ArrayList<>();
        boolean[] returnTainted = {false};

        visited.add(paramNode.id());
        worklist.add(paramNode.id());

        while (!worklist.isEmpty()) {
            int currentId = worklist.poll();
            DfgNode currentNode = dfg.node(currentId);

            if (currentNode.kind() == DfgNode.Kind.RETURN) {
                returnTainted[0] = true;
                // RETURN nodes have no outgoing DFG edges in this model -- nothing further to walk.
            }

            for (DfgEdge edge : dfg.edges()) {
                if (edge.from().id() != currentId) {
                    continue;
                }
                walkEdge(method, dfg, edge, paramNode, cameFrom, visited, worklist, sinkWitnesses);
            }
        }

        return new MethodSummary(returnTainted[0], List.copyOf(sinkWitnesses));
    }

    private void walkEdge(MethodKey method, DataFlowGraph dfg, DfgEdge edge, DfgNode paramNode,
                           Map<Integer, Integer> cameFrom, Set<Integer> visited, Deque<Integer> worklist,
                           List<SinkWitness> sinkWitnesses) {
        DfgNode to = edge.to();
        boolean isArgEdge = to.kind() == DfgNode.Kind.CALL && edge.label() != null && edge.label().startsWith("arg");
        boolean isReceiverEdge = to.kind() == DfgNode.Kind.CALL && "receiver".equals(edge.label());

        if (!isArgEdge && !isReceiverEdge) {
            if (visited.add(to.id())) {
                cameFrom.put(to.id(), edge.from().id());
                worklist.add(to.id());
            }
            return;
        }

        int argumentIndex = isReceiverEdge ? SinkRule.RECEIVER_INDEX : Integer.parseInt(edge.label().substring(3));
        Set<MethodKey> callees = calleeBySite.getOrDefault(method, Map.of()).getOrDefault(to.label(), Set.of());

        boolean sanitizedByEveryCallee = !callees.isEmpty()
                && callees.stream().allMatch(callee -> rules.sanitizers().sanitizes(callee, argumentIndex));
        if (sanitizedByEveryCallee) {
            return; // neutralized here: don't mark the call node (or its downstream) tainted
        }

        for (MethodKey callee : callees) {
            for (SinkRule sinkRule : rules.sinks().match(callee)) {
                if (sinkRule.isArgumentTainted(argumentIndex)) {
                    List<PathStep> path = reconstructPath(method, dfg, edge.from().id(), cameFrom, paramNode);
                    path.add(new PathStep(method, to));
                    sinkWitnesses.add(new SinkWitness(sinkRule, callee, to.label(), path));
                }
            }
        }

        boolean propagateOnward = isReceiverEdge || callees.isEmpty();
        if (!propagateOnward) {
            for (MethodKey callee : callees) {
                if (callGraph.isExternal(callee)) {
                    propagateOnward = true;
                    continue;
                }
                DataFlowGraph calleeDfg = dfgByKey.get(callee);
                if (calleeDfg == null) {
                    continue;
                }
                long calleeParamCount = calleeDfg.nodes().stream().filter(n -> n.kind() == DfgNode.Kind.PARAM).count();
                if (argumentIndex < 0 || argumentIndex >= calleeParamCount) {
                    continue;
                }
                MethodSummary calleeSummary = computeSummary(callee, argumentIndex);
                if (calleeSummary.returnTainted()) {
                    propagateOnward = true;
                }
                for (SinkWitness inner : calleeSummary.sinkWitnesses()) {
                    List<PathStep> stitched = reconstructPath(method, dfg, edge.from().id(), cameFrom, paramNode);
                    stitched.add(new PathStep(method, to));
                    stitched.addAll(inner.path());
                    sinkWitnesses.add(new SinkWitness(inner.sinkRule(), inner.sinkCalleeMethod(),
                            inner.sinkCallSite(), stitched));
                }
            }
        }

        if (propagateOnward && visited.add(to.id())) {
            cameFrom.put(to.id(), edge.from().id());
            worklist.add(to.id());
        }
    }

    private List<PathStep> reconstructPath(MethodKey method, DataFlowGraph dfg, int endNodeId,
                                            Map<Integer, Integer> cameFrom, DfgNode paramNode) {
        List<Integer> nodeIds = new ArrayList<>();
        Integer cursor = endNodeId;
        while (cursor != null) {
            nodeIds.add(cursor);
            cursor = cameFrom.get(cursor);
        }
        List<PathStep> path = new ArrayList<>();
        for (int i = nodeIds.size() - 1; i >= 0; i--) {
            path.add(new PathStep(method, dfg.node(nodeIds.get(i))));
        }
        if (path.isEmpty()) {
            path.add(new PathStep(method, paramNode));
        }
        return path;
    }

    /** One (method, parameter index) pair -- the unit a {@link MethodSummary} is memoized by. */
    private record ParamKey(MethodKey method, int paramIndex) {
    }
}
